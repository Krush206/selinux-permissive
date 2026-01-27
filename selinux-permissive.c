#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>

MODULE_LICENSE("BSD");
MODULE_AUTHOR("Matheus Garcia");
MODULE_DESCRIPTION("Disable SELinux enforcing.");
MODULE_VERSION("0.1.1");

static int *selinux_enforcing;
static void (*selnl_notify_setenforce)(int);
static void (*selinux_status_update_setenforce)(int);
static int (*avc_ss_reset)(u32);
static struct task_struct *thread;

static unsigned long enforcing_addr;
static unsigned long notify_addr;
static unsigned long status_update_addr;
static unsigned long ss_reset_addr;

module_param(enforcing_addr, ulong, 0644);
module_param(notify_addr, ulong, 0644);
module_param(status_update_addr, ulong, 0644);
module_param(ss_reset_addr, ulong, 0644);

static int selinux_permissive(void *data) {
    while(!kthread_should_stop())
    {
        if(!READ_ONCE(*selinux_enforcing))
        {
            msleep(100);
            continue;
        }
        WRITE_ONCE(*selinux_enforcing, 0);
        selnl_notify_setenforce(*selinux_enforcing);
        selinux_status_update_setenforce(*selinux_enforcing);
    }
    return 0;
}

static int __init selinux_permissive_start(void)
{
    if(!enforcing_addr ||
       !notify_addr ||
       !status_update_addr ||
       !ss_reset_addr)
        return -EINVAL;

    selinux_enforcing = (void *) enforcing_addr;
    selnl_notify_setenforce = (void *) notify_addr;
    selinux_status_update_setenforce = (void *) status_update_addr;
    avc_ss_reset = (void *) ss_reset_addr;
    thread = kthread_run(selinux_permissive, NULL, "selinux_permissive");

    return 0;
}

static void __exit selinux_permissive_stop(void)
{
    kthread_stop(thread);
    WRITE_ONCE(*selinux_enforcing, 1);
    avc_ss_reset(0);
    selnl_notify_setenforce(*selinux_enforcing);
    selinux_status_update_setenforce(*selinux_enforcing);
}

module_init(selinux_permissive_start);
module_exit(selinux_permissive_stop);

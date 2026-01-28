/*
 * Copyright (c) 2026 Matheus Garcia.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer. 
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. 
 * 
 * 3. Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Matheus Garcia");
MODULE_DESCRIPTION("Disable SELinux enforcing.");
MODULE_VERSION("0.3");

static void (*selnl_notify_setenforce)(int);
static void (*selinux_status_update_setenforce)(int);
static int (*avc_ss_reset)(u32);

static struct path path;

static ssize_t sel_read_permissive(struct file *filp,
                                   char __user *buf,
                                   size_t count,
                                   loff_t *ppos)
{
    return simple_read_from_buffer(buf, count, ppos, "0", (ssize_t) 1);
}

static const struct file_operations *sel_enforce_ops;
static const struct file_operations sel_permissive_ops = {
    .read = sel_read_permissive,
    .llseek = generic_file_llseek
};

static int __init selinux_permissive_start(void)
{
    struct inode *inode;

    if(kern_path("/sys/fs/selinux/enforce", LOOKUP_FOLLOW, &path))
        return -EINVAL;

    selnl_notify_setenforce = (void *) kallsyms_lookup_name("selnl_notify_setenforce");
    selinux_status_update_setenforce = (void *) kallsyms_lookup_name("selinux_status_update_setenforce");
    avc_ss_reset = (void *) kallsyms_lookup_name("avc_ss_reset");

    inode = d_inode(path.dentry);
    sel_enforce_ops = inode->i_fop;
    inode->i_fop = &sel_permissive_ops;

    selnl_notify_setenforce(0);
    selinux_status_update_setenforce(0);

    return 0;
}

static void __exit selinux_permissive_stop(void)
{
    struct inode *inode;
    int *selinux_enforcing;

    selinux_enforcing = (void *) kallsyms_lookup_name("selinux_enforcing");
    if(selinux_enforcing != NULL)
    {
        if(*selinux_enforcing)
            avc_ss_reset(0);
        selnl_notify_setenforce(*selinux_enforcing);
        selinux_status_update_setenforce(*selinux_enforcing);
    }
    else
    {
        avc_ss_reset(0);
        selnl_notify_setenforce(1);
        selinux_status_update_setenforce(1);
    }

    inode = d_inode(path.dentry);
    inode->i_fop = sel_enforce_ops;

    path_put(&path);
}

module_init(selinux_permissive_start);
module_exit(selinux_permissive_stop);

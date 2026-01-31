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
#include <linux/kallsyms.h>
#include <linux/lsm_hooks.h>

#define PATCH_SELINUX_HOOK(name, sym, fn)				\
    op = (void *) kallsyms_lookup_name(sym);				\
    if(op != NULL)							\
        list_for_each_entry(hp, &(heads->name), list)			\
            if(hp->hook.name == op)					\
            {								\
                orig.name = hp->hook.name;				\
                hp->hook.name = fn;					\
                break;							\
            }								\
    (void) 0

#define RESTORE_SELINUX_HOOK(name, fn)					\
    list_for_each_entry(hp, &(heads->name), list)			\
        if(hp->hook.name == fn)						\
        {								\
            hp->hook.name = orig.name;					\
            break;							\
        }								\
    (void) 0

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Matheus Garcia");
MODULE_DESCRIPTION("Disable SELinux enforcing.");
MODULE_VERSION("0.4.1");

static int dummy_selinux_binder_transaction(struct task_struct *from,
                                            struct task_struct *to)
{
    (void) from;
    (void) to;

    return 0;
}

static int dummy_selinux_capable(const struct cred *cred,
                                 struct user_namespace *ns,
                                 int cap,
                                 int audit)
{
    (void) cred;
    (void) ns;
    (void) cap;
    (void) audit;

    return 0;
}

static int dummy_selinux_inode_permission(struct inode *inode, int mask)
{
    (void) inode;
    (void) mask;

    return 0;
}

static int dummy_selinux_file_permission(struct file *file, int mask)
{
    (void) file;
    (void) mask;

    return 0;
}

static int dummy_selinux_task_kill(struct task_struct *p,
                                   struct siginfo *info,
                                   int sig,
                                   u32 secid)
{
    (void) p;
    (void) info;
    (void) sig;
    (void) secid;

    return 0;
}

static int dummy_selinux_socket_connect(struct socket *sock,
                                        struct sockaddr *address,
                                        int addrlen)
{
    (void) sock;
    (void) address;
    (void) addrlen;

    return 0;
}

static struct {
    int (*binder_transaction)(struct task_struct *from,
                              struct task_struct *to);
    int (*capable)(const struct cred *cred,
                   struct user_namespace *ns,
                   int cap,
                   int audit);
    int (*inode_permission)(struct inode *inode, int mask);
    int (*file_permission)(struct file *file, int mask);
    int (*task_kill)(struct task_struct *p,
                     struct siginfo *info,
                     int sig,
                     u32 secid);
    int (*socket_connect)(struct socket *sock,
                          struct sockaddr *address,
                          int addrlen);
} orig;

static int __init selinux_permissive_start(void)
{
    void *op;
    struct security_hook_list *hp;
    struct security_hook_heads *heads;

    heads = (void *) kallsyms_lookup_name("security_hook_heads");
    if(heads == NULL)
        return -EINVAL;
    PATCH_SELINUX_HOOK(binder_transaction,
                       "selinux_binder_transaction",
                       dummy_selinux_binder_transaction);
    PATCH_SELINUX_HOOK(capable,
                       "selinux_capable",
                       dummy_selinux_capable);
    PATCH_SELINUX_HOOK(inode_permission,
                       "selinux_inode_permission",
                       dummy_selinux_inode_permission);
    PATCH_SELINUX_HOOK(file_permission,
                       "selinux_file_permission",
                       dummy_selinux_file_permission);
    PATCH_SELINUX_HOOK(task_kill,
                       "selinux_task_kill",
                       dummy_selinux_task_kill);
    PATCH_SELINUX_HOOK(socket_connect,
                       "selinux_socket_connect",
                       dummy_selinux_socket_connect);

    return 0;
}

static void __exit selinux_permissive_stop(void)
{
    struct security_hook_list *hp;
    struct security_hook_heads *heads;

    heads = (void *) kallsyms_lookup_name("security_hook_heads");
    RESTORE_SELINUX_HOOK(binder_transaction,
                         dummy_selinux_binder_transaction);
    RESTORE_SELINUX_HOOK(capable,
                         dummy_selinux_capable);
    RESTORE_SELINUX_HOOK(inode_permission,
                         dummy_selinux_inode_permission);
    RESTORE_SELINUX_HOOK(file_permission,
                         dummy_selinux_file_permission);
    RESTORE_SELINUX_HOOK(task_kill,
                         dummy_selinux_task_kill);
    RESTORE_SELINUX_HOOK(socket_connect,
                         dummy_selinux_socket_connect);
}

module_init(selinux_permissive_start);
module_exit(selinux_permissive_stop);

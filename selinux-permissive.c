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

#define PATCH_SELINUX_HOOK(name, sym, fn, def)				\
    op = (void *) kallsyms_lookup_name(sym);				\
    if(op != NULL)							\
        list_for_each_entry(hp, &(heads->name), list)			\
            if(hp->hook.name == op)					\
            {								\
                def.name = hp->hook.name;				\
                WRITE_ONCE(hp->hook.name, fn);				\
                break;							\
            }								\
    (void) 0

#define APPLY_ALL_SELINUX_PATCHES(def)					\
    {									\
        void *op;							\
        struct security_hook_list *hp;					\
        struct security_hook_heads *heads;				\
									\
        heads = (void *) kallsyms_lookup_name("security_hook_heads");	\
        if(heads == NULL)						\
            return -EINVAL;						\
									\
        PATCH_SELINUX_HOOK(binder_set_context_mgr,			\
                           "selinux_binder_set_context_mgr",		\
                           dummy_selinux_binder_set_context_mgr,	\
                           def);					\
        PATCH_SELINUX_HOOK(binder_transaction,				\
                           "selinux_binder_transaction",		\
                           dummy_selinux_binder_transaction,		\
                           def);					\
        PATCH_SELINUX_HOOK(binder_transfer_binder,			\
                           "selinux_binder_transfer_binder",		\
                           dummy_selinux_binder_transfer_binder,	\
                           def);					\
        PATCH_SELINUX_HOOK(binder_transfer_file,			\
                           "selinux_binder_transfer_file",		\
                           dummy_selinux_binder_transfer_file,		\
                           def);					\
        PATCH_SELINUX_HOOK(ptrace_access_check,				\
                           "selinux_ptrace_access_check",		\
                           dummy_selinux_ptrace_access_check,		\
                           def);					\
        PATCH_SELINUX_HOOK(ptrace_traceme,				\
                           "selinux_ptrace_traceme",			\
                           dummy_selinux_ptrace_traceme,		\
                           def);					\
        PATCH_SELINUX_HOOK(capget,					\
                           "selinux_capget",				\
                           dummy_selinux_capget,			\
                           def);					\
        PATCH_SELINUX_HOOK(capset,					\
                           "selinux_capset",				\
                           dummy_selinux_capset,			\
                           def);					\
        PATCH_SELINUX_HOOK(capable,					\
                           "selinux_capable",				\
                           dummy_selinux_capable,			\
                           def);					\
        PATCH_SELINUX_HOOK(quotactl,					\
                           "selinux_quotactl",				\
                           dummy_selinux_quotactl,			\
                           def);					\
        PATCH_SELINUX_HOOK(quota_on,					\
                           "selinux_quota_on",				\
                           dummy_selinux_quota_on,			\
                           def);					\
        PATCH_SELINUX_HOOK(syslog,					\
                           "selinux_syslog",				\
                           dummy_selinux_syslog,			\
                           def);					\
        PATCH_SELINUX_HOOK(vm_enough_memory,				\
                           "selinux_vm_enough_memory",			\
                           dummy_selinux_vm_enough_memory,		\
                           def);					\
        PATCH_SELINUX_HOOK(netlink_send,				\
                           "selinux_netlink_send",			\
                           dummy_selinux_netlink_send,			\
                           def);					\
        PATCH_SELINUX_HOOK(bprm_set_creds,				\
                           "selinux_bprm_set_creds",			\
                           dummy_selinux_bprm_set_creds,		\
                           def);					\
        PATCH_SELINUX_HOOK(bprm_committing_creds,			\
                           "selinux_bprm_committing_creds",		\
                           dummy_selinux_bprm_committing_creds,		\
                           def);					\
        PATCH_SELINUX_HOOK(bprm_committed_creds,			\
                           "selinux_bprm_committed_creds",		\
                           dummy_selinux_bprm_committed_creds,		\
                           def);					\
        PATCH_SELINUX_HOOK(bprm_secureexec,				\
                           "selinux_bprm_secureexec",			\
                           dummy_selinux_bprm_secureexec,		\
                           def);					\
        PATCH_SELINUX_HOOK(sb_alloc_security,				\
                           "selinux_sb_alloc_security",			\
                           dummy_selinux_sb_alloc_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(sb_free_security,				\
                           "selinux_sb_free_security",			\
                           dummy_selinux_sb_free_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(sb_copy_data,				\
                           "selinux_sb_copy_data",			\
                           dummy_selinux_sb_copy_data,			\
                           def);					\
        PATCH_SELINUX_HOOK(sb_remount,					\
                           "selinux_sb_remount",			\
                           dummy_selinux_sb_remount,			\
                           def);					\
        PATCH_SELINUX_HOOK(sb_kern_mount,				\
                           "selinux_sb_kern_mount",			\
                           dummy_selinux_sb_kern_mount,			\
                           def);					\
        PATCH_SELINUX_HOOK(sb_show_options,				\
                           "selinux_sb_show_options",			\
                           dummy_selinux_sb_show_options,		\
                           def);					\
        PATCH_SELINUX_HOOK(sb_statfs,					\
                           "selinux_sb_statfs",				\
                           dummy_selinux_sb_statfs,			\
                           def);					\
        PATCH_SELINUX_HOOK(sb_mount,					\
                           "selinux_mount",				\
                           dummy_selinux_mount,				\
                           def);					\
        PATCH_SELINUX_HOOK(sb_umount,					\
                           "selinux_umount",				\
                           dummy_selinux_umount,			\
                           def);					\
        PATCH_SELINUX_HOOK(sb_set_mnt_opts,				\
                           "selinux_set_mnt_opts",			\
                           dummy_selinux_set_mnt_opts,			\
                           def);					\
        PATCH_SELINUX_HOOK(sb_clone_mnt_opts,				\
                           "selinux_sb_clone_mnt_opts",			\
                           dummy_selinux_sb_clone_mnt_opts,		\
                           def);					\
        PATCH_SELINUX_HOOK(sb_parse_opts_str,				\
                           "selinux_parse_opts_str",			\
                           dummy_selinux_parse_opts_str,		\
                           def);					\
        PATCH_SELINUX_HOOK(dentry_init_security,			\
                           "selinux_dentry_init_security",		\
                           dummy_selinux_dentry_init_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_alloc_security,			\
                           "selinux_inode_alloc_security",		\
                           dummy_selinux_inode_alloc_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_free_security,				\
                           "selinux_inode_free_security",		\
                           dummy_selinux_inode_free_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_init_security,				\
                           "selinux_inode_init_security",		\
                           dummy_selinux_inode_init_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_create,				\
                           "selinux_inode_create",			\
                           dummy_selinux_inode_create,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_link,					\
                           "selinux_inode_link",			\
                           dummy_selinux_inode_link,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_unlink,				\
                           "selinux_inode_unlink",			\
                           dummy_selinux_inode_unlink,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_symlink,				\
                           "selinux_inode_symlink",			\
                           dummy_selinux_inode_symlink,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_mkdir,					\
                           "selinux_inode_mkdir",			\
                           dummy_selinux_inode_mkdir,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_rmdir,					\
                           "selinux_inode_rmdir",			\
                           dummy_selinux_inode_rmdir,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_mknod,					\
                           "selinux_inode_mknod",			\
                           dummy_selinux_inode_mknod,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_rename,				\
                           "selinux_inode_rename",			\
                           dummy_selinux_inode_rename,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_readlink,				\
                           "selinux_inode_readlink",			\
                           dummy_selinux_inode_readlink,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_follow_link,				\
                           "selinux_inode_follow_link",			\
                           dummy_selinux_inode_follow_link,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_permission,				\
                           "selinux_inode_permission",			\
                           dummy_selinux_inode_permission,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_setattr,				\
                           "selinux_inode_setattr",			\
                           dummy_selinux_inode_setattr,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_getattr,				\
                           "selinux_inode_getattr",			\
                           dummy_selinux_inode_getattr,			\
                           def);					\
        PATCH_SELINUX_HOOK(inode_setxattr,				\
                           "selinux_inode_setxattr",			\
                           dummy_selinux_inode_setxattr,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_post_setxattr,				\
                           "selinux_inode_post_setxattr",		\
                           dummy_selinux_inode_post_setxattr,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_getxattr,				\
                           "selinux_inode_getxattr",			\
                           dummy_selinux_inode_getxattr,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_listxattr,				\
                           "selinux_inode_listxattr",			\
                           dummy_selinux_inode_listxattr,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_removexattr,				\
                           "selinux_inode_removexattr",			\
                           dummy_selinux_inode_removexattr,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_getsecurity,				\
                           "selinux_inode_getsecurity",			\
                           dummy_selinux_inode_getsecurity,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_setsecurity,				\
                           "selinux_inode_setsecurity",			\
                           dummy_selinux_inode_setsecurity,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_listsecurity,				\
                           "selinux_inode_listsecurity",		\
                           dummy_selinux_inode_listsecurity,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_getsecid,				\
                           "selinux_inode_getsecid",			\
                           dummy_selinux_inode_getsecid,		\
                           def);					\
        PATCH_SELINUX_HOOK(file_permission,				\
                           "selinux_file_permission",			\
                           dummy_selinux_file_permission,		\
                           def);					\
        PATCH_SELINUX_HOOK(file_alloc_security,				\
                           "selinux_file_alloc_security",		\
                           dummy_selinux_file_alloc_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(file_free_security,				\
                           "selinux_file_free_security",		\
                           dummy_selinux_file_free_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(file_ioctl,					\
                           "selinux_file_ioctl",			\
                           dummy_selinux_file_ioctl,			\
                           def);					\
        PATCH_SELINUX_HOOK(mmap_file,					\
                           "selinux_mmap_file",				\
                           dummy_selinux_mmap_file,			\
                           def);					\
        PATCH_SELINUX_HOOK(mmap_addr,					\
                           "selinux_mmap_addr",				\
                           dummy_selinux_mmap_addr,			\
                           def);					\
        PATCH_SELINUX_HOOK(file_mprotect,				\
                           "selinux_file_mprotect",			\
                           dummy_selinux_file_mprotect,			\
                           def);					\
        PATCH_SELINUX_HOOK(file_lock,					\
                           "selinux_file_lock",				\
                           dummy_selinux_file_lock,			\
                           def);					\
        PATCH_SELINUX_HOOK(file_fcntl,					\
                           "selinux_file_fcntl",			\
                           dummy_selinux_file_fcntl,			\
                           def);					\
        PATCH_SELINUX_HOOK(file_set_fowner,				\
                           "selinux_file_set_fowner",			\
                           dummy_selinux_file_set_fowner,		\
                           def);					\
        PATCH_SELINUX_HOOK(file_send_sigiotask,				\
                           "selinux_file_send_sigiotask",		\
                           dummy_selinux_file_send_sigiotask,		\
                           def);					\
        PATCH_SELINUX_HOOK(file_receive,				\
                           "selinux_file_receive",			\
                           dummy_selinux_file_receive,			\
                           def);					\
        PATCH_SELINUX_HOOK(file_open,					\
                           "selinux_file_open",				\
                           dummy_selinux_file_open,			\
                           def);					\
        PATCH_SELINUX_HOOK(task_create,					\
                           "selinux_task_create",			\
                           dummy_selinux_task_create,			\
                           def);					\
        PATCH_SELINUX_HOOK(cred_alloc_blank,				\
                           "selinux_cred_alloc_blank",			\
                           dummy_selinux_cred_alloc_blank,		\
                           def);					\
        PATCH_SELINUX_HOOK(cred_free,					\
                           "selinux_cred_free",				\
                           dummy_selinux_cred_free,			\
                           def);					\
        PATCH_SELINUX_HOOK(cred_prepare,				\
                           "selinux_cred_prepare",			\
                           dummy_selinux_cred_prepare,			\
                           def);					\
        PATCH_SELINUX_HOOK(cred_transfer,				\
                           "selinux_cred_transfer",			\
                           dummy_selinux_cred_transfer,			\
                           def);					\
        PATCH_SELINUX_HOOK(kernel_act_as,				\
                           "selinux_kernel_act_as",			\
                           dummy_selinux_kernel_act_as,			\
                           def);					\
        PATCH_SELINUX_HOOK(kernel_create_files_as,			\
                           "selinux_kernel_create_files_as",		\
                           dummy_selinux_kernel_create_files_as,	\
                           def);					\
        PATCH_SELINUX_HOOK(kernel_module_request,			\
                           "selinux_kernel_module_request",		\
                           dummy_selinux_kernel_module_request,		\
                           def);					\
        PATCH_SELINUX_HOOK(task_setpgid,				\
                           "selinux_task_setpgid",			\
                           dummy_selinux_task_setpgid,			\
                           def);					\
        PATCH_SELINUX_HOOK(task_getpgid,				\
                           "selinux_task_getpgid",			\
                           dummy_selinux_task_getpgid,			\
                           def);					\
        PATCH_SELINUX_HOOK(task_getsid,					\
                           "selinux_task_getsid",			\
                           dummy_selinux_task_getsid,			\
                           def);					\
        PATCH_SELINUX_HOOK(task_getsecid,				\
                           "selinux_task_getsecid",			\
                           dummy_selinux_task_getsecid,			\
                           def);					\
        PATCH_SELINUX_HOOK(task_setnice,				\
                           "selinux_task_setnice",			\
                           dummy_selinux_task_setnice,			\
                           def);					\
        PATCH_SELINUX_HOOK(task_setioprio,				\
                           "selinux_task_setioprio",			\
                           dummy_selinux_task_setioprio,		\
                           def);					\
        PATCH_SELINUX_HOOK(task_getioprio,				\
                           "selinux_task_getioprio",			\
                           dummy_selinux_task_getioprio,		\
                           def);					\
        PATCH_SELINUX_HOOK(task_setrlimit,				\
                           "selinux_task_setrlimit",			\
                           dummy_selinux_task_setrlimit,		\
                           def);					\
        PATCH_SELINUX_HOOK(task_setscheduler,				\
                           "selinux_task_setscheduler",			\
                           dummy_selinux_task_setscheduler,		\
                           def);					\
        PATCH_SELINUX_HOOK(task_getscheduler,				\
                           "selinux_task_getscheduler",			\
                           dummy_selinux_task_getscheduler,		\
                           def);					\
        PATCH_SELINUX_HOOK(task_movememory,				\
                           "selinux_task_movememory",			\
                           dummy_selinux_task_movememory,		\
                           def);					\
        PATCH_SELINUX_HOOK(task_kill,					\
                           "selinux_task_kill",				\
                           dummy_selinux_task_kill,			\
                           def);					\
        PATCH_SELINUX_HOOK(task_wait,					\
                           "selinux_task_wait",				\
                           dummy_selinux_task_wait,			\
                           def);					\
        PATCH_SELINUX_HOOK(task_to_inode,				\
                           "selinux_task_to_inode",			\
                           dummy_selinux_task_to_inode,			\
                           def);					\
        PATCH_SELINUX_HOOK(ipc_permission,				\
                           "selinux_ipc_permission",			\
                           dummy_selinux_ipc_permission,		\
                           def);					\
        PATCH_SELINUX_HOOK(ipc_getsecid,				\
                           "selinux_ipc_getsecid",			\
                           dummy_selinux_ipc_getsecid,			\
                           def);					\
        PATCH_SELINUX_HOOK(msg_msg_alloc_security,			\
                           "selinux_msg_msg_alloc_security",		\
                           dummy_selinux_msg_msg_alloc_security,	\
                           def);					\
        PATCH_SELINUX_HOOK(msg_msg_free_security,			\
                           "selinux_msg_msg_free_security",		\
                           dummy_selinux_msg_msg_free_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(msg_queue_alloc_security,			\
                           "selinux_msg_queue_alloc_security",		\
                           dummy_selinux_msg_queue_alloc_security,	\
                           def);					\
        PATCH_SELINUX_HOOK(msg_queue_free_security,			\
                           "selinux_msg_queue_free_security",		\
                           dummy_selinux_msg_queue_free_security,	\
                           def);					\
        PATCH_SELINUX_HOOK(msg_queue_associate,				\
                           "selinux_msg_queue_associate",		\
                           dummy_selinux_msg_queue_associate,		\
                           def);					\
        PATCH_SELINUX_HOOK(msg_queue_msgctl,				\
                           "selinux_msg_queue_msgctl",			\
                           dummy_selinux_msg_queue_msgctl,		\
                           def);					\
        PATCH_SELINUX_HOOK(msg_queue_msgsnd,				\
                           "selinux_msg_queue_msgsnd",			\
                           dummy_selinux_msg_queue_msgsnd,		\
                           def);					\
        PATCH_SELINUX_HOOK(msg_queue_msgrcv,				\
                           "selinux_msg_queue_msgrcv",			\
                           dummy_selinux_msg_queue_msgrcv,		\
                           def);					\
        PATCH_SELINUX_HOOK(shm_alloc_security,				\
                           "selinux_shm_alloc_security",		\
                           dummy_selinux_shm_alloc_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(shm_free_security,				\
                           "selinux_shm_free_security",			\
                           dummy_selinux_shm_free_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(shm_associate,				\
                           "selinux_shm_associate",			\
                           dummy_selinux_shm_associate,			\
                           def);					\
        PATCH_SELINUX_HOOK(shm_shmctl,					\
                           "selinux_shm_shmctl",			\
                           dummy_selinux_shm_shmctl,			\
                           def);					\
        PATCH_SELINUX_HOOK(shm_shmat,					\
                           "selinux_shm_shmat",				\
                           dummy_selinux_shm_shmat,			\
                           def);					\
        PATCH_SELINUX_HOOK(sem_alloc_security,				\
                           "selinux_sem_alloc_security",		\
                           dummy_selinux_sem_alloc_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(sem_free_security,				\
                           "selinux_sem_free_security",			\
                           dummy_selinux_sem_free_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(sem_associate,				\
                           "selinux_sem_associate",			\
                           dummy_selinux_sem_associate,			\
                           def);					\
        PATCH_SELINUX_HOOK(sem_semctl,					\
                           "selinux_sem_semctl",			\
                           dummy_selinux_sem_semctl,			\
                           def);					\
        PATCH_SELINUX_HOOK(sem_semop,					\
                           "selinux_sem_semop",				\
                           dummy_selinux_sem_semop,			\
                           def);					\
        PATCH_SELINUX_HOOK(d_instantiate,				\
                           "selinux_d_instantiate",			\
                           dummy_selinux_d_instantiate,			\
                           def);					\
        PATCH_SELINUX_HOOK(getprocattr,					\
                           "selinux_getprocattr",			\
                           dummy_selinux_getprocattr,			\
                           def);					\
        PATCH_SELINUX_HOOK(setprocattr,					\
                           "selinux_setprocattr",			\
                           dummy_selinux_setprocattr,			\
                           def);					\
        PATCH_SELINUX_HOOK(ismaclabel,					\
                           "selinux_ismaclabel",			\
                           dummy_selinux_ismaclabel,			\
                           def);					\
        PATCH_SELINUX_HOOK(secid_to_secctx,				\
                           "selinux_secid_to_secctx",			\
                           dummy_selinux_secid_to_secctx,		\
                           def);					\
        PATCH_SELINUX_HOOK(secctx_to_secid,				\
                           "selinux_secctx_to_secid",			\
                           dummy_selinux_secctx_to_secid,		\
                           def);					\
        PATCH_SELINUX_HOOK(release_secctx,				\
                           "selinux_release_secctx",			\
                           dummy_selinux_release_secctx,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_notifysecctx,				\
                           "selinux_inode_notifysecctx",		\
                           dummy_selinux_inode_notifysecctx,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_setsecctx,				\
                           "selinux_inode_setsecctx",			\
                           dummy_selinux_inode_setsecctx,		\
                           def);					\
        PATCH_SELINUX_HOOK(inode_getsecctx,				\
                           "selinux_inode_getsecctx",			\
                           dummy_selinux_inode_getsecctx,		\
                           def);					\
        PATCH_SELINUX_HOOK(unix_stream_connect,				\
                           "selinux_socket_unix_stream_connect",	\
                           dummy_selinux_socket_unix_stream_connect,	\
                           def);					\
        PATCH_SELINUX_HOOK(unix_may_send,				\
                           "selinux_socket_unix_may_send",		\
                           dummy_selinux_socket_unix_may_send,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_create,				\
                           "selinux_socket_create",			\
                           dummy_selinux_socket_create,			\
                           def);					\
        PATCH_SELINUX_HOOK(socket_post_create,				\
                           "selinux_socket_post_create",		\
                           dummy_selinux_socket_post_create,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_bind,					\
                           "selinux_socket_bind",			\
                           dummy_selinux_socket_bind,			\
                           def);					\
        PATCH_SELINUX_HOOK(socket_connect,				\
                           "selinux_socket_connect",			\
                           dummy_selinux_socket_connect,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_listen,				\
                           "selinux_socket_listen",			\
                           dummy_selinux_socket_listen,			\
                           def);					\
        PATCH_SELINUX_HOOK(socket_accept,				\
                           "selinux_socket_accept",			\
                           dummy_selinux_socket_accept,			\
                           def);					\
        PATCH_SELINUX_HOOK(socket_sendmsg,				\
                           "selinux_socket_sendmsg",			\
                           dummy_selinux_socket_sendmsg,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_recvmsg,				\
                           "selinux_socket_recvmsg",			\
                           dummy_selinux_socket_recvmsg,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_getsockname,				\
                           "selinux_socket_getsockname",		\
                           dummy_selinux_socket_getsockname,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_getpeername,				\
                           "selinux_socket_getpeername",		\
                           dummy_selinux_socket_getpeername,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_getsockopt,				\
                           "selinux_socket_getsockopt",			\
                           dummy_selinux_socket_getsockopt,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_setsockopt,				\
                           "selinux_socket_setsockopt",			\
                           dummy_selinux_socket_setsockopt,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_shutdown,				\
                           "selinux_socket_shutdown",			\
                           dummy_selinux_socket_shutdown,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_sock_rcv_skb,				\
                           "selinux_socket_sock_rcv_skb",		\
                           dummy_selinux_socket_sock_rcv_skb,		\
                           def);					\
        PATCH_SELINUX_HOOK(socket_getpeersec_stream,			\
                           "selinux_socket_getpeersec_stream",		\
                           dummy_selinux_socket_getpeersec_stream,	\
                           def);					\
        PATCH_SELINUX_HOOK(socket_getpeersec_dgram,			\
                           "selinux_socket_getpeersec_dgram",		\
                           dummy_selinux_socket_getpeersec_dgram,	\
                           def);					\
        PATCH_SELINUX_HOOK(sk_alloc_security,				\
                           "selinux_sk_alloc_security",			\
                           dummy_selinux_sk_alloc_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(sk_free_security,				\
                           "selinux_sk_free_security",			\
                           dummy_selinux_sk_free_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(sk_clone_security,				\
                           "selinux_sk_clone_security",			\
                           dummy_selinux_sk_clone_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(sk_getsecid,					\
                           "selinux_sk_getsecid",			\
                           dummy_selinux_sk_getsecid,			\
                           def);					\
        PATCH_SELINUX_HOOK(sock_graft,					\
                           "selinux_sock_graft",			\
                           dummy_selinux_sock_graft,			\
                           def);					\
        PATCH_SELINUX_HOOK(inet_conn_request,				\
                           "selinux_inet_conn_request",			\
                           dummy_selinux_inet_conn_request,		\
                           def);					\
        PATCH_SELINUX_HOOK(inet_csk_clone,				\
                           "selinux_inet_csk_clone",			\
                           dummy_selinux_inet_csk_clone,		\
                           def);					\
        PATCH_SELINUX_HOOK(inet_conn_established,			\
                           "selinux_inet_conn_established",		\
                           dummy_selinux_inet_conn_established,		\
                           def);					\
        PATCH_SELINUX_HOOK(secmark_relabel_packet,			\
                           "selinux_secmark_relabel_packet",		\
                           dummy_selinux_secmark_relabel_packet,	\
                           def);					\
        PATCH_SELINUX_HOOK(secmark_refcount_inc,			\
                           "selinux_secmark_refcount_inc",		\
                           dummy_selinux_secmark_refcount_inc,		\
                           def);					\
        PATCH_SELINUX_HOOK(secmark_refcount_dec,			\
                           "selinux_secmark_refcount_dec",		\
                           dummy_selinux_secmark_refcount_dec,		\
                           def);					\
        PATCH_SELINUX_HOOK(req_classify_flow,				\
                           "selinux_req_classify_flow",			\
                           dummy_selinux_req_classify_flow,		\
                           def);					\
        PATCH_SELINUX_HOOK(tun_dev_alloc_security,			\
                           "selinux_tun_dev_alloc_security",		\
                           dummy_selinux_tun_dev_alloc_security,	\
                           def);					\
        PATCH_SELINUX_HOOK(tun_dev_free_security,			\
                           "selinux_tun_dev_free_security",		\
                           dummy_selinux_tun_dev_free_security,		\
                           def);					\
        PATCH_SELINUX_HOOK(tun_dev_create,				\
                           "selinux_tun_dev_create",			\
                           dummy_selinux_tun_dev_create,		\
                           def);					\
        PATCH_SELINUX_HOOK(tun_dev_attach_queue,			\
                           "selinux_tun_dev_attach_queue",		\
                           dummy_selinux_tun_dev_attach_queue,		\
                           def);					\
        PATCH_SELINUX_HOOK(tun_dev_attach,				\
                           "selinux_tun_dev_attach",			\
                           dummy_selinux_tun_dev_attach,		\
                           def);					\
        PATCH_SELINUX_HOOK(tun_dev_open,				\
                           "selinux_tun_dev_open",			\
                           dummy_selinux_tun_dev_open,			\
                           def);					\
    } (void) 0

#ifdef CONFIG_SECURITY_NETWORK_XFRM
#define APPLY_ALL_XFRM_PATCHES(def)					\
    {									\
        void *op;							\
        struct security_hook_list *hp;					\
        struct security_hook_heads *heads;				\
									\
        heads = (void *) kallsyms_lookup_name("security_hook_heads");	\
        if(heads == NULL)						\
            return -EINVAL;						\
									\
        PATCH_SELINUX_HOOK(xfrm_policy_alloc_security,			\
                           "selinux_xfrm_policy_alloc",			\
                           dummy_selinux_xfrm_policy_alloc,		\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_policy_clone_security,			\
                           "selinux_xfrm_policy_clone",			\
                           dummy_selinux_xfrm_policy_clone,		\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_policy_free_security,			\
                           "selinux_xfrm_policy_free",			\
                           dummy_selinux_xfrm_policy_free,		\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_policy_delete_security,			\
                           "selinux_xfrm_policy_delete",		\
                           dummy_selinux_xfrm_policy_delete,		\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_state_alloc,				\
                           "selinux_xfrm_state_alloc",			\
                           dummy_selinux_xfrm_state_alloc,		\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_state_alloc_acquire,			\
                           "selinux_xfrm_state_alloc_acquire",		\
                           dummy_selinux_xfrm_state_alloc_acquire,	\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_state_free_security,			\
                           "selinux_xfrm_state_free",			\
                           dummy_selinux_xfrm_state_free,		\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_state_delete_security,			\
                           "selinux_xfrm_state_delete",			\
                           dummy_selinux_xfrm_state_delete,		\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_policy_lookup,				\
                           "selinux_xfrm_policy_lookup",		\
                           dummy_selinux_xfrm_policy_lookup,		\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_state_pol_flow_match,			\
                           "selinux_xfrm_state_pol_flow_match",		\
                           dummy_selinux_xfrm_state_pol_flow_match,	\
                           def);					\
        PATCH_SELINUX_HOOK(xfrm_decode_session,				\
                           "selinux_xfrm_decode_session",		\
                           dummy_selinux_xfrm_decode_session,		\
                           def);					\
    } (void) 0
#else
#define APPLY_ALL_XFRM_PATCHES(def) (void) 0
#endif

#ifdef CONFIG_KEY
#define APPLY_ALL_KEY_PATCHES(def)					\
    {									\
        void *op;							\
        struct security_hook_list *hp;					\
        struct security_hook_heads *heads;				\
									\
        heads = (void *) kallsyms_lookup_name("security_hook_heads");	\
        if(heads == NULL)						\
            return -EINVAL;						\
									\
        PATCH_SELINUX_HOOK(key_alloc,					\
                           "selinux_key_alloc",				\
                           dummy_selinux_key_alloc,			\
                           def);					\
        PATCH_SELINUX_HOOK(key_free,					\
                           "selinux_key_free",				\
                           dummy_selinux_key_free,			\
                           def);					\
        PATCH_SELINUX_HOOK(key_permission,				\
                           "selinux_key_permission",			\
                           dummy_selinux_key_permission,		\
                           def);					\
        PATCH_SELINUX_HOOK(key_getsecurity,				\
                           "selinux_key_getsecurity",			\
                           dummy_selinux_key_getsecurity,		\
                           def);					\
    } (void) 0
#else
#define APPLY_ALL_KEY_PATCHES(def) (void) 0
#endif

#ifdef CONFIG_AUDIT
#define APPLY_ALL_AUDIT_PATCHES(def)					\
    {									\
        void *op;							\
        struct security_hook_list *hp;					\
        struct security_hook_heads *heads;				\
									\
        heads = (void *) kallsyms_lookup_name("security_hook_heads");	\
        if(heads == NULL)						\
            return -EINVAL;						\
									\
        PATCH_SELINUX_HOOK(audit_rule_init,				\
                           "selinux_audit_rule_init",			\
                           dummy_selinux_audit_rule_init,		\
                           def);					\
        PATCH_SELINUX_HOOK(audit_rule_known,				\
                           "selinux_audit_rule_known",			\
                           dummy_selinux_audit_rule_known,		\
                           def);					\
        PATCH_SELINUX_HOOK(audit_rule_match,				\
                           "selinux_audit_rule_match",			\
                           dummy_selinux_audit_rule_match,		\
                           def);					\
        PATCH_SELINUX_HOOK(audit_rule_free,				\
                           "selinux_audit_rule_free",			\
                           dummy_selinux_audit_rule_free,		\
                           def);					\
    } (void) 0
#else
#define APPLY_ALL_AUDIT_PATCHES(def) (void) 0
#endif

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Matheus Garcia");
MODULE_DESCRIPTION("Disable SELinux enforcing.");
MODULE_VERSION("0.4");

static int dummy_selinux_set_mnt_opts(struct super_block *sb,
                                      struct security_mnt_opts *opts,
                                      unsigned long kern_flags,
                                      unsigned long *set_kern_flags)
{
    (void) sb;
    (void) opts;
    (void) kern_flags;
    (void) set_kern_flags;

    return 0;
}

static int dummy_selinux_sb_clone_mnt_opts(const struct super_block *oldsb,
                                           struct super_block *newsb)
{
    (void) oldsb;
    (void) newsb;

    return 0;
}

static int dummy_selinux_parse_opts_str(char *options,
                                        struct security_mnt_opts *opts)
{
    (void) options;
    (void) opts;

    return 0;
}

static int dummy_selinux_sb_show_options(struct seq_file *m, struct super_block *sb)
{
    (void) m;
    (void) sb;

    return 0;
}

static int dummy_selinux_binder_set_context_mgr(struct task_struct *mgr)
{
    (void) mgr;

    return 0;
}

static int dummy_selinux_binder_transaction(struct task_struct *from,
                                            struct task_struct *to)
{
    (void) from;
    (void) to;

    return 0;
}

static int dummy_selinux_binder_transfer_binder(struct task_struct *from,
                                                struct task_struct *to)
{
    (void) from;
    (void) to;

    return 0;
}

static int dummy_selinux_binder_transfer_file(struct task_struct *from,
                                              struct task_struct *to,
                                              struct file *file)
{
    (void) from;
    (void) to;
    (void) file;

    return 0;
}

static int dummy_selinux_ptrace_access_check(struct task_struct *child,
                                             unsigned int mode)
{
    (void) child;
    (void) mode;

    return 0;
}

static int dummy_selinux_ptrace_traceme(struct task_struct *parent)
{
    (void) parent;

    return 0;
}

static int dummy_selinux_capget(struct task_struct *target,
                                kernel_cap_t *effective,
                                kernel_cap_t *inheritable,
                                kernel_cap_t *permitted)
{
    (void) target;
    (void) effective;
    (void) inheritable;
    (void) permitted;

    return 0;
}

static int dummy_selinux_capset(struct cred *new,
                                const struct cred *old,
                                const kernel_cap_t *effective,
                                const kernel_cap_t *inheritable,
                                const kernel_cap_t *permitted)
{
    (void) new;
    (void) old;
    (void) effective;
    (void) inheritable;
    (void) permitted;

    return 0;
}

static int dummy_selinux_capable(const struct cred *cred,
                                 struct user_namespace *ns,
                                 int cap,
                                 int audit)
{
    return 0;
}

static int dummy_selinux_quotactl(int cmds, int type, int id, struct super_block *sb)
{
    (void) cmds;
    (void) type;
    (void) id;
    (void) sb;

    return 0;
}

static int dummy_selinux_quota_on(struct dentry *dentry)
{
    (void) dentry;

    return 0;
}

static int dummy_selinux_syslog(int type)
{
    (void) type;

    return 0;
}

static int dummy_selinux_vm_enough_memory(struct mm_struct *mm, long pages)
{
    (void) mm;
    (void) pages;

    return 0;
}

static int dummy_selinux_bprm_set_creds(struct linux_binprm *bprm)
{
    (void) bprm;

    return 0;
}

static int dummy_selinux_bprm_secureexec(struct linux_binprm *bprm)
{
    (void) bprm;

    return 0;
}

static void dummy_selinux_bprm_committing_creds(struct linux_binprm *bprm)
{
    (void) bprm;
}

static void dummy_selinux_bprm_committed_creds(struct linux_binprm *bprm)
{
    (void) bprm;
}

static int dummy_selinux_sb_alloc_security(struct super_block *sb)
{
    (void) sb;

    return 0;
}

static void dummy_selinux_sb_free_security(struct super_block *sb)
{
    (void) sb;
}

static int dummy_selinux_sb_copy_data(char *orig, char *copy)
{
    (void) orig;
    (void) copy;

    return 0;
}

static int dummy_selinux_sb_remount(struct super_block *sb, void *data)
{
    (void) sb;
    (void) data;

    return 0;
}

static int dummy_selinux_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
    (void) sb;
    (void) flags;
    (void) data;

    return 0;
}

static int dummy_selinux_sb_statfs(struct dentry *dentry)
{
    (void) dentry;

    return 0;
}

static int dummy_selinux_mount(const char *dev_name,
                               struct path *path,
                               const char *type,
                               unsigned long flags,
                               void *data)
{
    (void) dev_name;
    (void) path;
    (void) type;
    (void) flags;
    (void) data;

    return 0;
}

static int dummy_selinux_umount(struct vfsmount *mnt, int flags)
{
    (void) mnt;
    (void) flags;

    return 0;
}

static int dummy_selinux_inode_alloc_security(struct inode *inode)
{
    (void) inode;

    return 0;
}

static void dummy_selinux_inode_free_security(struct inode *inode)
{
    (void) inode;
}

static int dummy_selinux_dentry_init_security(struct dentry *dentry, int mode,
                                              struct qstr *name, void **ctx,
                                              u32 *ctxlen)
{
    (void) dentry;
    (void) mode;
    (void) name;
    (void) ctx;
    (void) ctxlen;

    return 0;
}

static int dummy_selinux_inode_init_security(struct inode *inode,
                                             struct inode *dir,
                                             const struct qstr *qstr,
                                             const char **name,
                                             void **value,
                                             size_t *len)
{
    (void) inode;
    (void) dir;
    (void) qstr;
    (void) name;
    (void) value;
    (void) len;

    return 0;
}

static int dummy_selinux_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    (void) dir;
    (void) dentry;
    (void) mode;

    return 0;
}

static int dummy_selinux_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    (void) old_dentry;
    (void) dir;
    (void) new_dentry;

    return 0;
}

static int dummy_selinux_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    (void) dir;
    (void) dentry;

    return 0;
}

static int dummy_selinux_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
    (void) dir;
    (void) dentry;
    (void) name;

    return 0;
}

static int dummy_selinux_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
    (void) dir;
    (void) dentry;
    (void) mask;

    return 0;
}

static int dummy_selinux_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    (void) dir;
    (void) dentry;

    return 0;
}

static int dummy_selinux_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
    (void) dir;
    (void) dentry;
    (void) mode;
    (void) dev;

    return 0;
}

static int dummy_selinux_inode_rename(struct inode *old_inode,
                                      struct dentry *old_dentry,
                                      struct inode *new_inode,
                                      struct dentry *new_dentry)
{
    (void) old_inode;
    (void) old_dentry;
    (void) new_inode;
    (void) new_dentry;

    return 0;
}

static int dummy_selinux_inode_readlink(struct dentry *dentry)
{
    (void) dentry;

    return 0;
}

static int dummy_selinux_inode_follow_link(struct dentry *dentry,
                                           struct inode *inode,
                                           bool rcu)
{
    (void) dentry;
    (void) inode;
    (void) rcu;

    return 0;
}

static int dummy_selinux_inode_permission(struct inode *inode, int mask)
{
    (void) inode;
    (void) mask;

    return 0;
}

static int dummy_selinux_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
    (void) dentry;
    (void) iattr;

    return 0;
}

static int dummy_selinux_inode_getattr(const struct path *path)
{
    (void) path;

    return 0;
}

static int dummy_selinux_inode_setxattr(struct dentry *dentry,
                                        const char *name,
                                        const void *value,
                                        size_t size,
                                        int flags)
{
    (void) dentry;
    (void) name;
    (void) value;
    (void) size;
    (void) flags;

    return 0;
}

static void dummy_selinux_inode_post_setxattr(struct dentry *dentry,
                                              const char *name,
                                              const void *value,
                                              size_t size,
                                              int flags)
{
    (void) dentry;
    (void) name;
    (void) value;
    (void) size;
    (void) flags;
}

static int dummy_selinux_inode_getxattr(struct dentry *dentry, const char *name)
{
    (void) dentry;
    (void) name;

    return 0;
}

static int dummy_selinux_inode_listxattr(struct dentry *dentry)
{
    (void) dentry;

    return 0;
}

static int dummy_selinux_inode_removexattr(struct dentry *dentry, const char *name)
{
    (void) dentry;
    (void) name;

    return 0;
}

static int dummy_selinux_inode_getsecurity(const struct inode *inode,
                                           const char *name,
                                           void **buffer,
                                           bool alloc)
{
    (void) inode;
    (void) name;
    (void) buffer;
    (void) alloc;

    return 0;
}

static int dummy_selinux_inode_setsecurity(struct inode *inode,
                                           const char *name,
                                           const void *value,
                                           size_t size,
                                           int flags)
{
    (void) inode;
    (void) name;
    (void) value;
    (void) size;
    (void) flags;

    return 0;
}

static int dummy_selinux_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
    (void) inode;
    (void) buffer;
    (void) buffer_size;

    return 0;
}

static void dummy_selinux_inode_getsecid(const struct inode *inode, u32 *secid)
{
    (void) inode;
    (void) secid;
}

static int dummy_selinux_file_permission(struct file *file, int mask)
{
    (void) file;
    (void) mask;

    return 0;
}

static int dummy_selinux_file_alloc_security(struct file *file)
{
    (void) file;

    return 0;
}

static void dummy_selinux_file_free_security(struct file *file)
{
    (void) file;
}

static int dummy_selinux_file_ioctl(struct file *file,
                                    unsigned int cmd,
                                    unsigned long arg)
{
    (void) file;
    (void) cmd;
    (void) arg;

    return 0;
}

static int dummy_selinux_mmap_addr(unsigned long addr)
{
    (void) addr;

    return 0;
}

static int dummy_selinux_mmap_file(struct file *file, unsigned long reqprot,
                                   unsigned long prot, unsigned long flags)
{
    (void) file;
    (void) reqprot;
    (void) prot;
    (void) flags;

    return 0;
}

static int dummy_selinux_file_mprotect(struct vm_area_struct *vma,
                                       unsigned long reqprot,
                                       unsigned long prot)
{
    (void) vma;
    (void) reqprot;
    (void) prot;

    return 0;
}

static int dummy_selinux_file_lock(struct file *file, unsigned int cmd)
{
    (void) file;
    (void) cmd;

    return 0;
}

static int dummy_selinux_file_fcntl(struct file *file,
                                    unsigned int cmd,
                                    unsigned long arg)
{
    (void) file;
    (void) cmd;
    (void) arg;

    return 0;
}

static void dummy_selinux_file_set_fowner(struct file *file)
{
    (void) file;
}

static int dummy_selinux_file_send_sigiotask(struct task_struct *tsk,
                                             struct fown_struct *fown,
                                             int signum)
{
    return 0;
}

static int dummy_selinux_file_receive(struct file *file)
{
    (void) file;

    return 0;
}

static int dummy_selinux_file_open(struct file *file, const struct cred *cred)
{
    (void) file;
    (void) cred;

    return 0;
}

static int dummy_selinux_task_create(unsigned long clone_flags)
{
    (void) clone_flags;

    return 0;
}

static int dummy_selinux_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
    (void) cred;
    (void) gfp;

    return 0;
}

static void dummy_selinux_cred_free(struct cred *cred)
{
    (void) cred;
}

static int dummy_selinux_cred_prepare(struct cred *new,
                                      const struct cred *old,
                                      gfp_t gfp)
{
    (void) new;
    (void) old;
    (void) gfp;

    return 0;
}

static void dummy_selinux_cred_transfer(struct cred *new, const struct cred *old)
{
    (void) new;
    (void) old;
}

static int dummy_selinux_kernel_act_as(struct cred *new, u32 secid)
{
    (void) new;
    (void) secid;

    return 0;
}

static int dummy_selinux_kernel_create_files_as(struct cred *new, struct inode *inode)
{
    (void) new;
    (void) inode;

    return 0;
}

static int dummy_selinux_kernel_module_request(char *kmod_name)
{
    (void) kmod_name;

    return 0;
}

static int dummy_selinux_task_setpgid(struct task_struct *p, pid_t pgid)
{
    (void) p;
    (void) pgid;

    return 0;
}

static int dummy_selinux_task_getpgid(struct task_struct *p)
{
    (void) p;

    return 0;
}

static int dummy_selinux_task_getsid(struct task_struct *p)
{
    (void) p;

    return 0;
}

static void dummy_selinux_task_getsecid(struct task_struct *p, u32 *secid)
{
    (void) p;
    (void) secid;
}

static int dummy_selinux_task_setnice(struct task_struct *p, int nice)
{
    (void) p;
    (void) nice;

    return 0;
}

static int dummy_selinux_task_setioprio(struct task_struct *p, int ioprio)
{
    (void) p;
    (void) ioprio;

    return 0;
}

static int dummy_selinux_task_getioprio(struct task_struct *p)
{
    (void) p;

    return 0;
}

static int dummy_selinux_task_setrlimit(struct task_struct *p,
                                        unsigned int resource,
                                        struct rlimit *new_rlim)
{
    (void) p;
    (void) resource;
    (void) new_rlim;

    return 0;
}

static int dummy_selinux_task_setscheduler(struct task_struct *p)
{
    (void) p;

    return 0;
}

static int dummy_selinux_task_getscheduler(struct task_struct *p)
{
    (void) p;

    return 0;
}

static int dummy_selinux_task_movememory(struct task_struct *p)
{
    (void) p;

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

static int dummy_selinux_task_wait(struct task_struct *p)
{
    (void) p;

    return 0;
}

static void dummy_selinux_task_to_inode(struct task_struct *p,
                                        struct inode *inode)
{
    (void) p;
    (void) inode;
}

static int dummy_selinux_socket_create(int family, int type,
                                       int protocol, int kern)
{
    (void) family;
    (void) type;
    (void) protocol;
    (void) kern;

    return 0;
}

static int dummy_selinux_socket_post_create(struct socket *sock, int family,
                                            int type, int protocol, int kern)
{
    (void) sock;
    (void) family;
    (void) type;
    (void) protocol;
    (void) kern;

    return 0;
}

static int dummy_selinux_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
    (void) sock;
    (void) address;
    (void) addrlen;

    return 0;
}

static int dummy_selinux_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
    (void) sock;
    (void) address;
    (void) addrlen;

    return 0;
}

static int dummy_selinux_socket_listen(struct socket *sock, int backlog)
{
    (void) sock;
    (void) backlog;

    return 0;
}

static int dummy_selinux_socket_accept(struct socket *sock, struct socket *newsock)
{
    (void) sock;
    (void) newsock;

    return 0;
}

static int dummy_selinux_socket_sendmsg(struct socket *sock,
                                        struct msghdr *msg,
                                        int size)
{
    (void) sock;
    (void) msg;
    (void) size;

    return 0;
}

static int dummy_selinux_socket_recvmsg(struct socket *sock,
                                        struct msghdr *msg,
                                        int size,
                                        int flags)
{
    (void) sock;
    (void) msg;
    (void) size;
    (void) flags;

    return 0;
}

static int dummy_selinux_socket_getsockname(struct socket *sock)
{
    (void) sock;

    return 0;
}

static int dummy_selinux_socket_getpeername(struct socket *sock)
{
    (void) sock;

    return 0;
}

static int dummy_selinux_socket_setsockopt(struct socket *sock, int level, int optname)
{
    (void) sock;
    (void) level;
    (void) optname;

    return 0;
}

static int dummy_selinux_socket_getsockopt(struct socket *sock,
                                           int level,
                                           int optname)
{
    (void) sock;
    (void) level;
    (void) optname;

    return 0;
}

static int dummy_selinux_socket_shutdown(struct socket *sock, int how)
{
    (void) sock;
    (void) how;

    return 0;
}

#ifdef CONFIG_SECURITY_NETWORK
static int dummy_selinux_socket_unix_stream_connect(struct sock *sock,
                                                    struct sock *other,
                                                    struct sock *newsk)
{
    (void) sock;
    (void) other;
    (void) newsk;

    return 0;
}

static int dummy_selinux_socket_unix_may_send(struct socket *sock,
                                              struct socket *other)
{
    (void) sock;
    (void) other;

    return 0;
}

static int dummy_selinux_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
    (void) sk;
    (void) skb;

    return 0;
}

static int dummy_selinux_socket_getpeersec_stream(struct socket *sock,
                                                  char __user *optval,
                                                  int __user *optlen,
                                                  unsigned len)
{
    (void) sock;
    (void) optval;
    (void) optlen;
    (void) len;

    return 0;
}

static int dummy_selinux_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
    (void) sock;
    (void) skb;
    (void) secid;

    return 0;
}

static int dummy_selinux_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
    (void) sk;
    (void) family;
    (void) priority;

    return 0;
}

static void dummy_selinux_sk_free_security(struct sock *sk)
{
    (void) sk;
}

static void dummy_selinux_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
    (void) sk;
    (void) newsk;
}

static void dummy_selinux_sk_getsecid(struct sock *sk, u32 *secid)
{
    (void) sk;
    (void) secid;
}

static void dummy_selinux_sock_graft(struct sock *sk, struct socket *parent)
{
    (void) sk;
    (void) parent;
}

static int dummy_selinux_inet_conn_request(struct sock *sk,
                                           struct sk_buff *skb,
                                           struct request_sock *req)
{
    (void) sk;
    (void) skb;
    (void) req;

    return 0;
}

static void dummy_selinux_inet_csk_clone(struct sock *newsk,
                                         const struct request_sock *req)
{
    (void) newsk;
    (void) req;
}

static void dummy_selinux_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
    (void) sk;
    (void) skb;
}

static int dummy_selinux_secmark_relabel_packet(u32 sid)
{
    (void) sid;

    return 0;
}

static void dummy_selinux_secmark_refcount_inc(void)
{
    ;
}

static void dummy_selinux_secmark_refcount_dec(void)
{
    ;
}

static void dummy_selinux_req_classify_flow(const struct request_sock *req,
                                            struct flowi *fl)
{
    (void) req;
    (void) fl;
}

static int dummy_selinux_tun_dev_alloc_security(void **security)
{
    (void) security;

    return 0;
}

static void dummy_selinux_tun_dev_free_security(void *security)
{
    (void) security;
}

static int dummy_selinux_tun_dev_create(void)
{
    return 0;
}

static int dummy_selinux_tun_dev_attach_queue(void *security)
{
    (void) security;

    return 0;
}

static int dummy_selinux_tun_dev_attach(struct sock *sk, void *security)
{
    (void) sk;
    (void) security;

    return 0;
}

static int dummy_selinux_tun_dev_open(void *security)
{
    (void) security;

    return 0;
}
#endif

static int dummy_selinux_netlink_send(struct sock *sk, struct sk_buff *skb)
{
    (void) sk;
    (void) skb;

    return 0;
}

static int dummy_selinux_msg_msg_alloc_security(struct msg_msg *msg)
{
    (void) msg;

    return 0;
}

static void dummy_selinux_msg_msg_free_security(struct msg_msg *msg)
{
    (void) msg;
}

static int dummy_selinux_msg_queue_alloc_security(struct msg_queue *msq)
{
    (void) msq;

    return 0;
}

static void dummy_selinux_msg_queue_free_security(struct msg_queue *msq)
{
    (void) msq;
}

static int dummy_selinux_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
    (void) msq;
    (void) msqflg;

    return 0;
}

static int dummy_selinux_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
    (void) msq;
    (void) cmd;

    return 0;
}

static int dummy_selinux_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg)
{
    (void) msq;
    (void) msg;
    (void) msqflg;

    return 0;
}

static int dummy_selinux_msg_queue_msgrcv(struct msg_queue *msq,
                                          struct msg_msg *msg,
                                          struct task_struct *target,
                                          long type,
                                          int mode)
{
    (void) msq;
    (void) msg;
    (void) target;
    (void) type;
    (void) mode;

    return 0;
}

static int dummy_selinux_shm_alloc_security(struct shmid_kernel *shp)
{
    (void) shp;

    return 0;
}

static void dummy_selinux_shm_free_security(struct shmid_kernel *shp)
{
    (void) shp;
}

static int dummy_selinux_shm_associate(struct shmid_kernel *shp, int shmflg)
{
    (void) shp;
    (void) shmflg;

    return 0;
}

static int dummy_selinux_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
    (void) shp;
    (void) cmd;

    return 0;
}

static int dummy_selinux_shm_shmat(struct shmid_kernel *shp,
                                   char __user *shmaddr,
                                   int shmflag)
{
    (void) shp;
    (void) shmaddr;
    (void) shmflag;

    return 0;
}

static int dummy_selinux_sem_alloc_security(struct sem_array *sma)
{
    (void) sma;

    return 0;
}

static void dummy_selinux_sem_free_security(struct sem_array *sma)
{
    (void) sma;
}

static int dummy_selinux_sem_associate(struct sem_array *sma, int semflg)
{
    (void) sma;
    (void) semflg;

    return 0;
}

static int dummy_selinux_sem_semctl(struct sem_array *sma, int cmd)
{
    (void) sma;
    (void) cmd;

    return 0;
}

static int dummy_selinux_sem_semop(struct sem_array *sma,
                                   struct sembuf *sops,
                                   unsigned nsops,
                                   int alter)
{
    (void) sma;
    (void) sops;
    (void) nsops;
    (void) alter;

    return 0;
}

static int dummy_selinux_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
    (void) ipcp;
    (void) flag;

    return 0;
}

static void dummy_selinux_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
    (void) ipcp;
    (void) secid;
}

static void dummy_selinux_d_instantiate(struct dentry *dentry, struct inode *inode)
{
    (void) dentry;
    (void) inode;
}

static int dummy_selinux_getprocattr(struct task_struct *p,
                                     char *name,
                                     char **value)
{
    (void) p;
    (void) name;
    (void) value;

    return 0;
}

static int dummy_selinux_setprocattr(struct task_struct *p,
                                     char *name,
                                     void *value,
                                     size_t size)
{
    (void) p;
    (void) name;
    (void) value;
    (void) size;

    return 0;
}

static int dummy_selinux_ismaclabel(const char *name)
{
    (void) name;

    return 0;
}

static int dummy_selinux_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
    (void) secid;
    (void) secdata;
    (void) seclen;

    return 0;
}

static int dummy_selinux_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
    (void) secdata;
    (void) seclen;
    (void) secid;

    return 0;
}

static void dummy_selinux_release_secctx(char *secdata, u32 seclen)
{
    (void) secdata;
    (void) seclen;
}

static int dummy_selinux_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
    (void) inode;
    (void) ctx;
    (void) ctxlen;

    return 0;
}

static int dummy_selinux_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
    (void) dentry;
    (void) ctx;
    (void) ctxlen;

    return 0;
}

static int dummy_selinux_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
    (void) inode;
    (void) ctx;
    (void) ctxlen;

    return 0;
}

#ifdef CONFIG_KEY
static int dummy_selinux_key_alloc(struct key *k,
                                   const struct cred *cred,
                                   unsigned long flags)
{
    (void) k;
    (void) cred;
    (void) flags;

    return 0;
}

static void dummy_selinux_key_free(struct key *k)
{
    (void) k;
}

static int dummy_selinux_key_permission(key_ref_t key_ref,
                                        const struct cred *cred,
                                        unsigned perm)
{
    (void) key_ref;
    (void) cred;
    (void) perm;

    return 0;
}

static int dummy_selinux_key_getsecurity(struct key *key, char **_buffer)
{
    (void) key;
    (void) _buffer;

    return 0;
}
#endif

#ifdef CONFIG_AUDIT
static int dummy_selinux_audit_rule_init(u32 field, u32 op,
                                         char *rulestr, void **lsmrule)
{
    (void) field;
    (void) op;
    (void) rulestr;
    (void) lsmrule;

    return 0;
}

static int dummy_selinux_audit_rule_known(struct audit_krule *krule)
{
    (void) krule;

    return 0;
}

static int dummy_selinux_audit_rule_match(u32 secid, u32 field, u32 op,
                                          void *lsmrule,
                                          struct audit_context *actx)
{
    (void) secid;
    (void) field;
    (void) op;
    (void) lsmrule;
    (void) actx;

    return 0;
}

static void dummy_selinux_audit_rule_free(void *lsmrule)
{
    (void) lsmrule;
}
#endif

static struct {
	int (*binder_set_context_mgr)(struct task_struct *mgr);
	int (*binder_transaction)(struct task_struct *from,
					struct task_struct *to);
	int (*binder_transfer_binder)(struct task_struct *from,
					struct task_struct *to);
	int (*binder_transfer_file)(struct task_struct *from,
					struct task_struct *to,
					struct file *file);

	int (*ptrace_access_check)(struct task_struct *child,
					unsigned int mode);
	int (*ptrace_traceme)(struct task_struct *parent);
	int (*capget)(struct task_struct *target, kernel_cap_t *effective,
			kernel_cap_t *inheritable, kernel_cap_t *permitted);
	int (*capset)(struct cred *new, const struct cred *old,
			const kernel_cap_t *effective,
			const kernel_cap_t *inheritable,
			const kernel_cap_t *permitted);
	int (*capable)(const struct cred *cred, struct user_namespace *ns,
			int cap, int audit);
	int (*quotactl)(int cmds, int type, int id, struct super_block *sb);
	int (*quota_on)(struct dentry *dentry);
	int (*syslog)(int type);
	int (*settime)(const struct timespec *ts, const struct timezone *tz);
	int (*vm_enough_memory)(struct mm_struct *mm, long pages);

	int (*bprm_set_creds)(struct linux_binprm *bprm);
	int (*bprm_check_security)(struct linux_binprm *bprm);
	int (*bprm_secureexec)(struct linux_binprm *bprm);
	void (*bprm_committing_creds)(struct linux_binprm *bprm);
	void (*bprm_committed_creds)(struct linux_binprm *bprm);

	int (*sb_alloc_security)(struct super_block *sb);
	void (*sb_free_security)(struct super_block *sb);
	int (*sb_copy_data)(char *orig, char *copy);
	int (*sb_remount)(struct super_block *sb, void *data);
	int (*sb_kern_mount)(struct super_block *sb, int flags, void *data);
	int (*sb_show_options)(struct seq_file *m, struct super_block *sb);
	int (*sb_statfs)(struct dentry *dentry);
	int (*sb_mount)(const char *dev_name, struct path *path,
			const char *type, unsigned long flags, void *data);
	int (*sb_umount)(struct vfsmount *mnt, int flags);
	int (*sb_pivotroot)(struct path *old_path, struct path *new_path);
	int (*sb_set_mnt_opts)(struct super_block *sb,
				struct security_mnt_opts *opts,
				unsigned long kern_flags,
				unsigned long *set_kern_flags);
	int (*sb_clone_mnt_opts)(const struct super_block *oldsb,
					struct super_block *newsb);
	int (*sb_parse_opts_str)(char *options, struct security_mnt_opts *opts);
	int (*dentry_init_security)(struct dentry *dentry, int mode,
					struct qstr *name, void **ctx,
					u32 *ctxlen);


#ifdef CONFIG_SECURITY_PATH
	int (*path_unlink)(struct path *dir, struct dentry *dentry);
	int (*path_mkdir)(struct path *dir, struct dentry *dentry,
				umode_t mode);
	int (*path_rmdir)(struct path *dir, struct dentry *dentry);
	int (*path_mknod)(struct path *dir, struct dentry *dentry,
				umode_t mode, unsigned int dev);
	int (*path_truncate)(struct path *path);
	int (*path_symlink)(struct path *dir, struct dentry *dentry,
				const char *old_name);
	int (*path_link)(struct dentry *old_dentry, struct path *new_dir,
				struct dentry *new_dentry);
	int (*path_rename)(struct path *old_dir, struct dentry *old_dentry,
				struct path *new_dir,
				struct dentry *new_dentry);
	int (*path_chmod)(struct path *path, umode_t mode);
	int (*path_chown)(struct path *path, kuid_t uid, kgid_t gid);
	int (*path_chroot)(struct path *path);
#endif

	int (*inode_alloc_security)(struct inode *inode);
	void (*inode_free_security)(struct inode *inode);
	int (*inode_init_security)(struct inode *inode, struct inode *dir,
					const struct qstr *qstr,
					const char **name, void **value,
					size_t *len);
	int (*inode_create)(struct inode *dir, struct dentry *dentry,
				umode_t mode);
	int (*inode_link)(struct dentry *old_dentry, struct inode *dir,
				struct dentry *new_dentry);
	int (*inode_unlink)(struct inode *dir, struct dentry *dentry);
	int (*inode_symlink)(struct inode *dir, struct dentry *dentry,
				const char *old_name);
	int (*inode_mkdir)(struct inode *dir, struct dentry *dentry,
				umode_t mode);
	int (*inode_rmdir)(struct inode *dir, struct dentry *dentry);
	int (*inode_mknod)(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev);
	int (*inode_rename)(struct inode *old_dir, struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry);
	int (*inode_readlink)(struct dentry *dentry);
	int (*inode_follow_link)(struct dentry *dentry, struct inode *inode,
				 bool rcu);
	int (*inode_permission)(struct inode *inode, int mask);
	int (*inode_setattr)(struct dentry *dentry, struct iattr *attr);
	int (*inode_getattr)(const struct path *path);
	int (*inode_setxattr)(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags);
	void (*inode_post_setxattr)(struct dentry *dentry, const char *name,
					const void *value, size_t size,
					int flags);
	int (*inode_getxattr)(struct dentry *dentry, const char *name);
	int (*inode_listxattr)(struct dentry *dentry);
	int (*inode_removexattr)(struct dentry *dentry, const char *name);
	int (*inode_need_killpriv)(struct dentry *dentry);
	int (*inode_killpriv)(struct dentry *dentry);
	int (*inode_getsecurity)(const struct inode *inode, const char *name,
					void **buffer, bool alloc);
	int (*inode_setsecurity)(struct inode *inode, const char *name,
					const void *value, size_t size,
					int flags);
	int (*inode_listsecurity)(struct inode *inode, char *buffer,
					size_t buffer_size);
	void (*inode_getsecid)(const struct inode *inode, u32 *secid);

	int (*file_permission)(struct file *file, int mask);
	int (*file_alloc_security)(struct file *file);
	void (*file_free_security)(struct file *file);
	int (*file_ioctl)(struct file *file, unsigned int cmd,
				unsigned long arg);
	int (*mmap_addr)(unsigned long addr);
	int (*mmap_file)(struct file *file, unsigned long reqprot,
				unsigned long prot, unsigned long flags);
	int (*file_mprotect)(struct vm_area_struct *vma, unsigned long reqprot,
				unsigned long prot);
	int (*file_lock)(struct file *file, unsigned int cmd);
	int (*file_fcntl)(struct file *file, unsigned int cmd,
				unsigned long arg);
	void (*file_set_fowner)(struct file *file);
	int (*file_send_sigiotask)(struct task_struct *tsk,
					struct fown_struct *fown, int sig);
	int (*file_receive)(struct file *file);
	int (*file_open)(struct file *file, const struct cred *cred);

	int (*task_create)(unsigned long clone_flags);
	void (*task_free)(struct task_struct *task);
	int (*cred_alloc_blank)(struct cred *cred, gfp_t gfp);
	void (*cred_free)(struct cred *cred);
	int (*cred_prepare)(struct cred *new, const struct cred *old,
				gfp_t gfp);
	void (*cred_transfer)(struct cred *new, const struct cred *old);
	int (*kernel_act_as)(struct cred *new, u32 secid);
	int (*kernel_create_files_as)(struct cred *new, struct inode *inode);
	int (*kernel_fw_from_file)(struct file *file, char *buf, size_t size);
	int (*kernel_module_request)(char *kmod_name);
	int (*kernel_module_from_file)(struct file *file);
	int (*task_fix_setuid)(struct cred *new, const struct cred *old,
				int flags);
	int (*task_setpgid)(struct task_struct *p, pid_t pgid);
	int (*task_getpgid)(struct task_struct *p);
	int (*task_getsid)(struct task_struct *p);
	void (*task_getsecid)(struct task_struct *p, u32 *secid);
	int (*task_setnice)(struct task_struct *p, int nice);
	int (*task_setioprio)(struct task_struct *p, int ioprio);
	int (*task_getioprio)(struct task_struct *p);
	int (*task_setrlimit)(struct task_struct *p, unsigned int resource,
				struct rlimit *new_rlim);
	int (*task_setscheduler)(struct task_struct *p);
	int (*task_getscheduler)(struct task_struct *p);
	int (*task_movememory)(struct task_struct *p);
	int (*task_kill)(struct task_struct *p, struct siginfo *info,
				int sig, u32 secid);
	int (*task_wait)(struct task_struct *p);
	int (*task_prctl)(int option, unsigned long arg2, unsigned long arg3,
				unsigned long arg4, unsigned long arg5);
	void (*task_to_inode)(struct task_struct *p, struct inode *inode);

	int (*ipc_permission)(struct kern_ipc_perm *ipcp, short flag);
	void (*ipc_getsecid)(struct kern_ipc_perm *ipcp, u32 *secid);

	int (*msg_msg_alloc_security)(struct msg_msg *msg);
	void (*msg_msg_free_security)(struct msg_msg *msg);

	int (*msg_queue_alloc_security)(struct msg_queue *msq);
	void (*msg_queue_free_security)(struct msg_queue *msq);
	int (*msg_queue_associate)(struct msg_queue *msq, int msqflg);
	int (*msg_queue_msgctl)(struct msg_queue *msq, int cmd);
	int (*msg_queue_msgsnd)(struct msg_queue *msq, struct msg_msg *msg,
				int msqflg);
	int (*msg_queue_msgrcv)(struct msg_queue *msq, struct msg_msg *msg,
				struct task_struct *target, long type,
				int mode);

	int (*shm_alloc_security)(struct shmid_kernel *shp);
	void (*shm_free_security)(struct shmid_kernel *shp);
	int (*shm_associate)(struct shmid_kernel *shp, int shmflg);
	int (*shm_shmctl)(struct shmid_kernel *shp, int cmd);
	int (*shm_shmat)(struct shmid_kernel *shp, char __user *shmaddr,
				int shmflg);

	int (*sem_alloc_security)(struct sem_array *sma);
	void (*sem_free_security)(struct sem_array *sma);
	int (*sem_associate)(struct sem_array *sma, int semflg);
	int (*sem_semctl)(struct sem_array *sma, int cmd);
	int (*sem_semop)(struct sem_array *sma, struct sembuf *sops,
				unsigned nsops, int alter);

	int (*netlink_send)(struct sock *sk, struct sk_buff *skb);

	void (*d_instantiate)(struct dentry *dentry, struct inode *inode);

	int (*getprocattr)(struct task_struct *p, char *name, char **value);
	int (*setprocattr)(struct task_struct *p, char *name, void *value,
				size_t size);
	int (*ismaclabel)(const char *name);
	int (*secid_to_secctx)(u32 secid, char **secdata, u32 *seclen);
	int (*secctx_to_secid)(const char *secdata, u32 seclen, u32 *secid);
	void (*release_secctx)(char *secdata, u32 seclen);

	int (*inode_notifysecctx)(struct inode *inode, void *ctx, u32 ctxlen);
	int (*inode_setsecctx)(struct dentry *dentry, void *ctx, u32 ctxlen);
	int (*inode_getsecctx)(struct inode *inode, void **ctx, u32 *ctxlen);

#ifdef CONFIG_SECURITY_NETWORK
	int (*unix_stream_connect)(struct sock *sock, struct sock *other,
					struct sock *newsk);
	int (*unix_may_send)(struct socket *sock, struct socket *other);

	int (*socket_create)(int family, int type, int protocol, int kern);
	int (*socket_post_create)(struct socket *sock, int family, int type,
					int protocol, int kern);
	int (*socket_bind)(struct socket *sock, struct sockaddr *address,
				int addrlen);
	int (*socket_connect)(struct socket *sock, struct sockaddr *address,
				int addrlen);
	int (*socket_listen)(struct socket *sock, int backlog);
	int (*socket_accept)(struct socket *sock, struct socket *newsock);
	int (*socket_sendmsg)(struct socket *sock, struct msghdr *msg,
				int size);
	int (*socket_recvmsg)(struct socket *sock, struct msghdr *msg,
				int size, int flags);
	int (*socket_getsockname)(struct socket *sock);
	int (*socket_getpeername)(struct socket *sock);
	int (*socket_getsockopt)(struct socket *sock, int level, int optname);
	int (*socket_setsockopt)(struct socket *sock, int level, int optname);
	int (*socket_shutdown)(struct socket *sock, int how);
	int (*socket_sock_rcv_skb)(struct sock *sk, struct sk_buff *skb);
	int (*socket_getpeersec_stream)(struct socket *sock,
					char __user *optval,
					int __user *optlen, unsigned len);
	int (*socket_getpeersec_dgram)(struct socket *sock,
					struct sk_buff *skb, u32 *secid);
	int (*sk_alloc_security)(struct sock *sk, int family, gfp_t priority);
	void (*sk_free_security)(struct sock *sk);
	void (*sk_clone_security)(const struct sock *sk, struct sock *newsk);
	void (*sk_getsecid)(struct sock *sk, u32 *secid);
	void (*sock_graft)(struct sock *sk, struct socket *parent);
	int (*inet_conn_request)(struct sock *sk, struct sk_buff *skb,
					struct request_sock *req);
	void (*inet_csk_clone)(struct sock *newsk,
				const struct request_sock *req);
	void (*inet_conn_established)(struct sock *sk, struct sk_buff *skb);
	int (*secmark_relabel_packet)(u32 secid);
	void (*secmark_refcount_inc)(void);
	void (*secmark_refcount_dec)(void);
	void (*req_classify_flow)(const struct request_sock *req,
					struct flowi *fl);
	int (*tun_dev_alloc_security)(void **security);
	void (*tun_dev_free_security)(void *security);
	int (*tun_dev_create)(void);
	int (*tun_dev_attach_queue)(void *security);
	int (*tun_dev_attach)(struct sock *sk, void *security);
	int (*tun_dev_open)(void *security);
#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
	int (*xfrm_policy_alloc_security)(struct xfrm_sec_ctx **ctxp,
					  struct xfrm_user_sec_ctx *sec_ctx,
						gfp_t gfp);
	int (*xfrm_policy_clone_security)(struct xfrm_sec_ctx *old_ctx,
						struct xfrm_sec_ctx **new_ctx);
	void (*xfrm_policy_free_security)(struct xfrm_sec_ctx *ctx);
	int (*xfrm_policy_delete_security)(struct xfrm_sec_ctx *ctx);
	int (*xfrm_state_alloc)(struct xfrm_state *x,
				struct xfrm_user_sec_ctx *sec_ctx);
	int (*xfrm_state_alloc_acquire)(struct xfrm_state *x,
					struct xfrm_sec_ctx *polsec,
					u32 secid);
	void (*xfrm_state_free_security)(struct xfrm_state *x);
	int (*xfrm_state_delete_security)(struct xfrm_state *x);
	int (*xfrm_policy_lookup)(struct xfrm_sec_ctx *ctx, u32 fl_secid,
					u8 dir);
	int (*xfrm_state_pol_flow_match)(struct xfrm_state *x,
						struct xfrm_policy *xp,
						const struct flowi *fl);
	int (*xfrm_decode_session)(struct sk_buff *skb, u32 *secid, int ckall);
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */

	/* key management security hooks */
#ifdef CONFIG_KEYS
	int (*key_alloc)(struct key *key, const struct cred *cred,
				unsigned long flags);
	void (*key_free)(struct key *key);
	int (*key_permission)(key_ref_t key_ref, const struct cred *cred,
				unsigned perm);
	int (*key_getsecurity)(struct key *key, char **_buffer);
#endif	/* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
	int (*audit_rule_init)(u32 field, u32 op, char *rulestr,
				void **lsmrule);
	int (*audit_rule_known)(struct audit_krule *krule);
	int (*audit_rule_match)(u32 secid, u32 field, u32 op, void *lsmrule,
				struct audit_context *actx);
	void (*audit_rule_free)(void *lsmrule);
#endif /* CONFIG_AUDIT */
} orig;

static int __init selinux_permissive_start(void)
{
    preempt_disable();
    APPLY_ALL_SELINUX_PATCHES(orig);
    APPLY_ALL_XFRM_PATCHES(orig);
    APPLY_ALL_KEY_PATCHES(orig);
    APPLY_ALL_AUDIT_PATCHES(orig);
    preempt_enable();

    return 0;
}

static void __exit selinux_permissive_stop(void)
{
}

module_init(selinux_permissive_start);
module_exit(selinux_permissive_stop);

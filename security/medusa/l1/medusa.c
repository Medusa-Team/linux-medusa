// SPDX-License-Identifier: GPL-2.0

#ifdef CONFIG_SECURITY_MEDUSA

#include <linux/binfmts.h>
#include <linux/module.h>
#include <linux/sched/task.h>

#include "l4/auth_server.h"
#include "l4/comm.h"
#include "l3/registry.h"
#include "l3/arch.h"
#include "l1/inode.h"
#include "l1/task.h"
#include "l1/ipc.h"
#include "l1/socket.h"
#include "l1/fuck.h"
#include "../../../../fs/mount.h" /* real_mount(), struct mount */

/* Used by `medusa_l1_creds_for_exec` */
bool trigger_loaded;

// TODO remove unused l2 events?
//medusa_create(dentry, mode)
//medusa_readlink(dentry)

static int medusa_l1_creds_for_exec(struct linux_binprm *bprm)
{
	if (IS_ENABLED(CONFIG_SECURITY_MEDUSA_START_AUTH_SERVER_BEFORE_INIT) &&
	    !trigger_loaded) {
		/* If bprm->filename isn't the trigger task, do nothing. */
		if (strcmp(bprm->filename,
			   CONFIG_SECURITY_MEDUSA_AUTH_SERVER_TRIGGER)) {
			med_pr_info("Exec of non-trigger task '%s' detected",
				    bprm->filename);

			/* Medusa will be inactive before running the AS. */
			return 0;
		}

		med_pr_info("Exec of trigger task '%s' detected - start AS",
			    bprm->filename);
		start_auth_server();
		wait_for_auth_server();

		trigger_loaded = 1;
		return 0;
	}

	if (medusa_exec(bprm) == MED_DENY)
		return -EACCES;
	return 0;
}

/*
 * Caller function security_inode_alloc() is called only from
 * inode_init_always(). Invariant: if the inode security blob size is not zero
 * and the inode in question is dynamically allocated by slab, inode security
 * blob *must be* allocated. Implication: inode security blob in Medusa's
 * inode_alloc_security() is always allocated.
 *
 * Are there in the kernel some inodes defined statically?
 */
int medusa_l1_inode_alloc_security(struct inode *inode)
{
	struct medusa_l1_inode_s *med = inode_security(inode);

	hash_init(med->fuck);
	init_med_object(&med->med_object);

	return 0;
}

void medusa_l1_inode_free_security(struct inode *inode)
{
	struct medusa_l1_inode_s *med = inode_security(inode);

	if (unlikely(med && !hash_empty(med->fuck)))
		fuck_free(med);
}

/*
static int medusa_l1_inode_permission(struct inode *inode, int mask)
{
	int no_block = mask & MAY_NOT_BLOCK;

	if (no_block)
		return -ECHILD;

	mask &= (MAY_READ | MAY_WRITE | MAY_EXEC | MAY_APPEND);
	// Existence test. TODO: What about Medusa SEE permission?
	if (mask == 0)
		return 0;

	if (medusa_permission(inode, mask) == MED_DENY)
		return -EACCES;
	return 0;
}
*/

#ifdef CONFIG_SECURITY_PATH

static int medusa_l1_path_mknod(const struct path *dir, struct dentry *dentry,
				umode_t mode, unsigned int dev)
{
	if (medusa_mknod(dir, dentry, mode, dev) == MED_DENY)
		return -EACCES;
	return 0;
}

static int medusa_l1_path_mkdir(const struct path *dir, struct dentry *dentry,
				umode_t mode)
{
	//char buf[128];
	//char *pos = d_absolute_path(dir, buf, 127);
	//if (!IS_ERR(pos))
	//	med_pr_info("mkdir: %s", pos);
	if (medusa_mkdir(dir, dentry, mode) == MED_DENY)
		return -EACCES;
	return 0;
}

static int medusa_l1_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	//struct mount *mnt = real_mount(dir->mnt);
	//med_pr_info("rmdir dir dentry: %pd\n", dir->dentry);
	//med_pr_info("rmdir dentry: %pd\n", dentry);
	//med_pr_info("mountpoint: %pd, vfs mnt root: %pd\n", mnt->mnt_mountpoint, mnt->mnt.mnt_root);
	if (medusa_rmdir(dir, dentry) == MED_DENY)
		return -EACCES;
	return 0;
}

static int medusa_l1_path_unlink(const struct path *dir, struct dentry *dentry)
{
	//char buf[128];
	//char *pos = d_absolute_path(dir, buf, 127);
	//if (!IS_ERR(pos))
	//	med_pr_info("unlink: %s", pos);
	if (medusa_unlink(dir, dentry) == MED_DENY)
		return -EPERM;
	return 0;
}

static int medusa_l1_path_symlink(const struct path *dir, struct dentry *dentry,
				  const char *old_name)
{
	if (medusa_symlink(dir, dentry, old_name) == MED_DENY)
		return -EACCES;

	return 0;
}

static int medusa_l1_path_link(struct dentry *old_dentry,
			       const struct path *new_dir,
			       struct dentry *new_dentry)
{
	if (medusa_link(old_dentry, new_dir, new_dentry) == MED_DENY)
		return -EACCES;
	return 0;
}

static int medusa_l1_path_rename(const struct path *old_path,
				 struct dentry *old_dentry,
				 const struct path *new_path,
				 struct dentry *new_dentry,
				 unsigned int flags)
{
	if (medusa_rename(old_path, old_dentry, new_path, new_dentry) == MED_DENY)
		return -EACCES;
	return 0;
}

static int medusa_l1_path_truncate(const struct path *path)
{
	if (medusa_truncate(path) == MED_DENY)
		return -EACCES;
	return 0;
}

static int medusa_l1_path_chmod(const struct path *path, umode_t mode)
{
	if (medusa_chmod(path, mode) == MED_DENY)
		return -EACCES;
	//return validate_fuck(path);
	return 0;
}

static int medusa_l1_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	if (medusa_chown(path, uid, gid) == MED_DENY)
		return -EACCES;
	//return validate_fuck(path);
	return 0;
}

static int medusa_l1_path_chroot(const struct path *path)
{
	if (medusa_chroot(path) == MED_DENY)
		return -EACCES;
	return 0;
}

#endif  /* CONFIG_SECURITY_PATH */

static int medusa_l1_file_fcntl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	if (medusa_fcntl(file, cmd, arg) == MED_DENY)
		return -EACCES;
	return 0;
}

static int medusa_l1_file_open(struct file *file)
{
	if (medusa_open(file) == MED_DENY)
		return -EACCES;
	//return validate_fuck(&file->f_path);
	return 0;
}

/**
 * medusa_l1_file_truncate - Target for security_file_truncate().
 *
 * @file: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int medusa_l1_file_truncate(struct file *file)
{
	if (medusa_truncate(&file->f_path) == MED_DENY)
		return -EACCES;
	return 0;
}

static int medusa_l1_task_fix_setuid(struct cred *new,
				     const struct cred *old,
				     int flags)
{
	if (medusa_setresuid(new, old, flags) == MED_DENY)
		return -EACCES;
	return 0;
}

/*
 * Function security_task_alloc() is called only from fork().
 * If there is no memory for security blob allocation, -ENOMEM is returned
 * to fork(). Invariant: each task *must have* a task security blob
 * allocated, if its size is not zero. Implication: no checks for Medusa's
 * task security blob are required.
 */
int medusa_l1_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
	struct medusa_l1_task_s *old = task_security(current);
	struct medusa_l1_task_s *med = task_security(task);

	/*  current == task iff initializing task with pid == 0  */
	if (unlikely(current == task)) {
		init_med_object(&med->med_object);
		init_med_subject(&med->med_subject);
	} else {
		*med = *old;
	}

	mutex_init(&med->validation_in_progress);
	med->validation_depth_nesting = 1;

#ifndef CONFIG_SECURITY_MEDUSA_MONITOR_KTHREADS
	/* Kernel threads have a superpower... Don't try to restrict them! */
	if ((task->flags & PF_KTHREAD) || !task->mm)
		med_magic_not_monitored(&med->med_object);
#endif
#ifdef CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL
	med->self = NULL;
	refcount_set(&med->rcu_cb_set, 0);
#endif /* CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL */

	return 0;
}

void medusa_l1_task_free(struct task_struct *task)
{
}

#ifdef CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL
static int medusa_l1_task_kill(struct task_struct *p, struct kernel_siginfo *info,
			       int sig, const struct cred *cred)
{
	if (medusa_sendsig(p, info, sig, cred) == MED_DENY)
		return -EACCES;

	return 0;
}
#endif /* CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL */

//IPC hooks

/*
 * Helper function, not a LSM hook.
 *
 * medusa_l1_ipc_alloc_security()
 * ^
 * |
 * |-- medusa_l1_msg_queue_alloc_security()
 * |       ^
 * |       |-- security_queue_msg_alloc()
 * |           ^
 * |           |-- newque() (create a new msg queue, ipc/msg.c)
 * |
 * |-- medusa_l1_shm_alloc_security()
 * |       ^
 * |       |-- security_shm_alloc()
 * |           ^
 * |           |-- newseg() (create a new shared memory segment, ipc/shm.c)
 * |
 * --- medusa_l1_sem_alloc_security()
 *         ^
 *         |-- security_sem_alloc()
 *             ^
 *             |-- newary() (create a new semaphore set, ipc/sem.c)
 *
 * If allocation of an IPC security blob failed in security_*_alloc()
 * function(s), IPC object is not created. Invariant: In an existing IPC
 * object there is always allocated related security blob, if its blob size in
 * a LSM is not zero. Implication: no checks for Medusa's IPC security blob
 * are required.
 */
int medusa_l1_ipc_alloc_security(struct kern_ipc_perm *ipcp,
				 unsigned int ipc_class)
{
	struct medusa_l1_ipc_s *med = ipc_security(ipcp);

	init_med_object(&med->med_object);
	med->ipc_class = ipc_class;
	return 0;
}

//int medusa_l1_msg_msg_alloc_security(struct msg_msg *msg)
//{
	/*
	 * called only from load_msg() (see ipc/msgutil.c
	 * IPC security calls do not apply to struct msg_msg itself,
	 * only to msg_queue struct.
	 */
//	return 0;
//}

//void medusa_l1_msg_msg_free_security(struct msg_msg *msg)
//{
	/*
	 * called only from free_msg() (see ipc/msgutil.c
	 * IPC security calls do not apply to struct msg_msg itself,
	 * only to msg_queue struct.
	 */
//}

int medusa_l1_msg_queue_alloc_security(struct kern_ipc_perm *msq)
{
	return medusa_l1_ipc_alloc_security(msq, MED_IPC_MSG);
}

int medusa_l1_shm_alloc_security(struct kern_ipc_perm *shp)
{
	return medusa_l1_ipc_alloc_security(shp, MED_IPC_SHM);
}

int medusa_l1_sem_alloc_security(struct kern_ipc_perm *sma)
{
	return medusa_l1_ipc_alloc_security(sma, MED_IPC_SEM);
}

int medusa_queue_associate(struct kern_ipc_perm *ipcp, int flag)
{
	return medusa_ipc_associate(ipcp, flag, "queue_associate");
}

int medusa_shm_associate(struct kern_ipc_perm *ipcp, int flag)
{
	return medusa_ipc_associate(ipcp, flag, "shm_associate");
}

int medusa_sem_associate(struct kern_ipc_perm *ipcp, int flag)
{
	return medusa_ipc_associate(ipcp, flag, "sem_associate");
}

int medusa_queue_ctl(struct kern_ipc_perm *ipcp, int cmd)
{
	return medusa_ipc_ctl(ipcp, cmd, "msgctl");
}

int medusa_shm_ctl(struct kern_ipc_perm *ipcp, int cmd)
{
	return medusa_ipc_ctl(ipcp, cmd, "shmctl");
}

int medusa_sem_ctl(struct kern_ipc_perm *ipcp, int cmd)
{
	return medusa_ipc_ctl(ipcp, cmd, "semctl");
}

#ifdef CONFIG_SECURITY_NETWORK

/*
 * static int medusa_l1_socket_create(int family, int type, int protocol, int kern)
 * {
 *	if (kern)
 *		return 0;
 *
 *	if (medusa_socket_create(family, type, protocol) == MED_DENY)
 *		return -EACCES;
 *
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_post_create(struct socket *sock, int family, int type,
 *				int protocol, int kern)
 * {
 *	struct medusa_l1_socket_s *sk_sec;
 *
 *	if (sock->sk) {
 *		sk_sec = sock_security(sock->sk);
 *		sk_sec->addrlen = 0;
 *	}
 *
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_bind(struct socket *sock, struct sockaddr *address,
 *				int addrlen)
 * {
 *	if (!sock->sk) {
 *		return 0;
 *	}
 *
 *	if (medusa_socket_bind(sock, address, addrlen) == MED_DENY)
 *		return -EACCES;
 *
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_connect(struct socket *sock, struct sockaddr *address,
 *				int addrlen)
 * {
 *	if (!sock->sk) {
 *		return 0;
 *	}
 *
 *	if (medusa_socket_connect(sock, address, addrlen) == MED_DENY)
 *		return -EACCES;
 *
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_listen(struct socket *sock, int backlog)
 * {
 *	if (!sock->sk) {
 *		return 0;
 *	}
 *
 *	if (medusa_socket_listen(sock, backlog) == MED_DENY)
 *		return -EACCES;
 *
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_accept(struct socket *sock, struct socket *newsock)
 * {
 *	if (!sock->sk) {
 *		return 0;
 *	}
 *
 *	if (medusa_socket_accept(sock, newsock) == MED_DENY)
 *		return -EACCES;
 *
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
 * {
 *	if (!sock->sk) {
 *		return 0;
 *	}
 *
 *	if (medusa_socket_sendmsg(sock, msg, size) == MED_DENY)
 *		return -EACCES;
 *
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_recvmsg(struct socket *sock, struct msghdr *msg,
 *				int size, int flags)
 * {
 *	if (!sock->sk) {
 *		return 0;
 *	}
 *
 *	if (medusa_socket_recvmsg(sock, msg, size, flags) == MED_DENY)
 *		return -EACCES;
 *
 *	return 0;
 * }
 */


/*
 * static int medusa_l1_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
 * {
 *	sk->sk_security = (struct medusa_l1_socket_s*) kmalloc(sizeof(struct medusa_l1_socket_s), GFP_KERNEL);
 *
 *	if (!sk->sk_security) {
 *		return -1;
 *	}
 *
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_sk_free_security(struct sock *sk)
 * {
 *	struct medusa_l1_socket_s *med;
 *
 *	if (sk->sk_security != NULL) {
 *		med = sk->sk_security;
 *		sk->sk_security = NULL;
 *		kfree(med);
 *	}
 * }
 */

/*
 * static void medusa_l1_sk_clone_security(const struct sock *sk, struct sock *newsk)
 * {
 *	struct medusa_l1_socket_s *sk_sec = sk->sk_security;
 *	struct medusa_l1_socket_s *newsk_sec = newsk->sk_security;
 *
 *	newsk_sec = (struct medusa_l1_socket_s*) kmalloc(sizeof(struct medusa_l1_socket_s), GFP_KERNEL);
 *	newsk_sec->addrlen = 0;
 *	newsk_sec->med_object = sk_sec->med_object;
 * }
 */

#endif	/* CONFIG_SECURITY_NETWORK */

/*
 * static void medusa_l1_d_instantiate(struct dentry *dentry, struct inode *inode)
 * {
 * }
 */

static struct security_hook_list medusa_l1_hooks[] = {
	LSM_HOOK_INIT(bprm_creds_for_exec, medusa_l1_creds_for_exec),
	//LSM_HOOK_INIT(bprm_creds_from_file, medusa_l1_creds_from_file),
	//LSM_HOOK_INIT(bprm_check_security, medusa_l1_bprm_check_security),
	//LSM_HOOK_INIT(bprm_committing_creds, medusa_l1_bprm_committing_creds),
	//LSM_HOOK_INIT(bprm_committed_creds, medusa_l1_bprm_committed_creds),

	//LSM_HOOK_INIT(fs_context_dup, medusa_l1_fs_context_dup),
	//LSM_HOOK_INIT(fs_context_parse_param, medusa_l1_fs_context_parse_param),
	//LSM_HOOK_INIT(sb_alloc_security, medusa_l1_sb_alloc_security),
	//LSM_HOOK_INIT(sb_delete, medusa_l1_sb_delete),
	//LSM_HOOK_INIT(sb_free_security, medusa_l1_sb_free_security),
	//LSM_HOOK_INIT(sb_free_mnt_opts, medusa_l1_sb_free_mnt_opts),
	//LSM_HOOK_INIT(sb_eat_lsm_opts, medusa_l1_sb_eat_lsm_opts),
	//LSM_HOOK_INIT(sb_mnt_opts_compat, medusa_l1_sb_mnt_opts_compat),
	//LSM_HOOK_INIT(sb_remount, medusa_l1_sb_remount),
	//LSM_HOOK_INIT(sb_kern_mount, medusa_l1_sb_kern_mount),
	//LSM_HOOK_INIT(sb_show_options, medusa_l1_sb_show_options),
	//LSM_HOOK_INIT(sb_statfs, medusa_l1_sb_statfs),
	//LSM_HOOK_INIT(sb_mount, medusa_l1_sb_mount),
	//LSM_HOOK_INIT(sb_umount, medusa_l1_sb_umount),
	//LSM_HOOK_INIT(sb_pivotroot, medusa_l1_sb_pivotroot),
	//LSM_HOOK_INIT(sb_set_mnt_opts, medusa_l1_sb_set_mnt_opts),
	//LSM_HOOK_INIT(sb_clone_mnt_opts, medusa_l1_sb_clone_mnt_opts),
	//LSM_HOOK_INIT(sb_add_mnt_opt, medusa_l1_sb_add_mnt_opt),
	//LSM_HOOK_INIT(move_mount, medusa_l1_move_mount),
	//LSM_HOOK_INIT(dentry_init_security, medusa_l1_dentry_init_security),
	//LSM_HOOK_INIT(dentry_create_files_as, medusa_l1_dentry_create_files_as),

#ifdef CONFIG_SECURITY_PATH
	LSM_HOOK_INIT(path_unlink, medusa_l1_path_unlink),
	LSM_HOOK_INIT(path_mkdir, medusa_l1_path_mkdir),
	LSM_HOOK_INIT(path_rmdir, medusa_l1_path_rmdir),
	LSM_HOOK_INIT(path_mknod, medusa_l1_path_mknod),
	LSM_HOOK_INIT(path_truncate, medusa_l1_path_truncate),
	LSM_HOOK_INIT(path_symlink, medusa_l1_path_symlink),
	LSM_HOOK_INIT(path_link, medusa_l1_path_link),
	LSM_HOOK_INIT(path_rename, medusa_l1_path_rename),
	LSM_HOOK_INIT(path_chmod, medusa_l1_path_chmod),
	LSM_HOOK_INIT(path_chown, medusa_l1_path_chown),
	LSM_HOOK_INIT(path_chroot, medusa_l1_path_chroot),
#endif /* CONFIG_SECURITY_PATH */

	//LSM_HOOK_INIT(inode_permission, medusa_l1_inode_permission),

	//LSM_HOOK_INIT(file_permission, medusa_l1_file_permission),
	//LSM_HOOK_INIT(file_alloc_security, medusa_l1_file_alloc_security),
	//LSM_HOOK_INIT(file_free_security, medusa_l1_file_free_security),
	//LSM_HOOK_INIT(file_ioctl, medusa_l1_file_ioctl),
	//LSM_HOOK_INIT(mmap_addr, medusa_l1_mmap_addr),
	//LSM_HOOK_INIT(mmap_file, medusa_l1_mmap_file),
	//LSM_HOOK_INIT(file_mprotect, medusa_l1_file_mprotect),
	//LSM_HOOK_INIT(file_lock, medusa_l1_file_lock),
	LSM_HOOK_INIT(file_fcntl, medusa_l1_file_fcntl),
	//LSM_HOOK_INIT(file_set_fowner, medusa_l1_file_set_fowner),
	//LSM_HOOK_INIT(file_send_sigiotask, medusa_l1_file_send_sigiotask),
	//LSM_HOOK_INIT(file_receive, medusa_l1_file_receive),
	LSM_HOOK_INIT(file_open, medusa_l1_file_open),
	LSM_HOOK_INIT(file_truncate, medusa_l1_file_truncate),

	//LSM_HOOK_INIT(cred_alloc_blank, medusa_l1_cred_alloc_blank),
	//LSM_HOOK_INIT(cred_free, medusa_l1_cred_free),
	//LSM_HOOK_INIT(cred_prepare, medusa_l1_cred_prepare),
	//LSM_HOOK_INIT(cred_transfer, medusa_l1_cred_transfer),
	//LSM_HOOK_INIT(cred_getsecid, medusa_l1_cred_getsecid),
	//LSM_HOOK_INIT(kernel_act_as, medusa_l1_kernel_act_as),
	//LSM_HOOK_INIT(kernel_create_files_as, medusa_l1_kernel_create_files_as),
	//LSM_HOOK_INIT(kernel_module_request, medusa_l1_kernel_module_request),
	//LSM_HOOK_INIT(kernel_load_data, medusa_l1_kernel_load_data),
	//LSM_HOOK_INIT(kernel_post_load_data, medusa_l1_kernel_post_load_data),
	//LSM_HOOK_INIT(kernel_read_file, medusa_l1_read_file),
	//LSM_HOOK_INIT(kernel_post_read_file, medusa_l1_post_read_file),
	LSM_HOOK_INIT(task_fix_setuid, medusa_l1_task_fix_setuid),
	//LSM_HOOK_INIT(task_fix_setgid, medusa_l1_task_fix_setgid),
	//LSM_HOOK_INIT(task_setpgid, medusa_l1_task_setpgid),
	//LSM_HOOK_INIT(task_getpgid, medusa_l1_task_getpgid),
	//LSM_HOOK_INIT(task_getsid, medusa_l1_task_getsid),
	//LSM_HOOK_INIT(task_getsecid, medusa_l1_task_getsecid),
	//LSM_HOOK_INIT(task_setnice, medusa_l1_task_setnice),
	//LSM_HOOK_INIT(task_setioprio, medusa_l1_task_setioprio),
	//LSM_HOOK_INIT(task_getioprio, medusa_l1_task_getioprio),
	//LSM_HOOK_INIT(task_prlimit, medusa_l1_task_prlimit),
	//LSM_HOOK_INIT(task_setrlimit, medusa_l1_task_setrlimit),
	//LSM_HOOK_INIT(task_setscheduler, medusa_l1_task_setscheduler),
	//LSM_HOOK_INIT(task_getscheduler, medusa_l1_task_getscheduler),
	//LSM_HOOK_INIT(task_movememory, medusa_l1_task_movememory),
#ifdef CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL
	LSM_HOOK_INIT(task_kill, medusa_l1_task_kill),
#endif /* CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL */
	//LSM_HOOK_INIT(task_prctl, medusa_l1_task_prctl),
	//LSM_HOOK_INIT(task_to_inode, medusa_l1_task_to_inode),

	LSM_HOOK_INIT(ipc_permission, medusa_ipc_permission),
	//LSM_HOOK_INIT(ipc_getsecid, medusa_l1_ipc_getsecid),
	LSM_HOOK_INIT(msg_queue_associate, medusa_queue_associate),
	LSM_HOOK_INIT(msg_queue_msgctl, medusa_queue_ctl),
	LSM_HOOK_INIT(msg_queue_msgsnd, medusa_ipc_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv, medusa_ipc_msgrcv),
	LSM_HOOK_INIT(shm_associate, medusa_shm_associate),
	LSM_HOOK_INIT(shm_shmctl, medusa_shm_ctl),
	LSM_HOOK_INIT(shm_shmat, medusa_ipc_shmat),
	LSM_HOOK_INIT(sem_associate, medusa_sem_associate),
	LSM_HOOK_INIT(sem_semctl, medusa_sem_ctl),
	LSM_HOOK_INIT(sem_semop, medusa_ipc_semop),

	//LSM_HOOK_INIT(d_instantiate, medusa_l1_d_instantiate),

#ifdef CONFIG_SECURITY_NETWORK
	/*
	 * LSM_HOOK_INIT(socket_create, medusa_l1_socket_create),
	 * LSM_HOOK_INIT(socket_post_create, medusa_l1_socket_post_create),
	 * LSM_HOOK_INIT(socket_bind, medusa_l1_socket_bind),
	 * LSM_HOOK_INIT(socket_connect, medusa_l1_socket_connect),
	 * LSM_HOOK_INIT(socket_listen, medusa_l1_socket_listen),
	 * LSM_HOOK_INIT(socket_accept, medusa_l1_socket_accept),
	 * LSM_HOOK_INIT(socket_sendmsg, medusa_l1_socket_sendmsg),
	 * LSM_HOOK_INIT(socket_recvmsg, medusa_l1_socket_recvmsg),
	 * LSM_HOOK_INIT(sk_alloc_security, medusa_l1_sk_alloc_security),
	 * LSM_HOOK_INIT(sk_free_security, medusa_l1_sk_free_security),
	 * LSM_HOOK_INIT(sk_clone_security, medusa_l1_sk_clone_security),
	 */
#endif /* CONFIG_SECURITY_NETWORK */
};

struct security_hook_list medusa_l1_hooks_alloc[] = {
	LSM_HOOK_INIT(task_alloc, medusa_l1_task_alloc),
	LSM_HOOK_INIT(task_free, medusa_l1_task_free),

	LSM_HOOK_INIT(inode_alloc_security, medusa_l1_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security, medusa_l1_inode_free_security),

	LSM_HOOK_INIT(shm_alloc_security, medusa_l1_shm_alloc_security),
	//LSM_HOOK_INIT(shm_free_security, medusa_l1_shm_free_security),
	LSM_HOOK_INIT(sem_alloc_security, medusa_l1_sem_alloc_security),
	//LSM_HOOK_INIT(sem_free_security, medusa_l1_sem_free_security),
	LSM_HOOK_INIT(msg_queue_alloc_security, medusa_l1_msg_queue_alloc_security),
	//LSM_HOOK_INIT(msg_queue_free_security, medusa_l1_msg_queue_free_security),
	//LSM_HOOK_INIT(msg_msg_alloc_security, medusa_l1_msg_msg_alloc_security),
	//LSM_HOOK_INIT(msg_msg_free_security, medusa_l1_msg_msg_free_security),
};

static int __init medusa_l1_init(void)
{
	/* set the security info for the task pid 0 on boot cpu */
	medusa_l1_task_alloc(current, 0);

	/* register the hooks */
	security_add_hooks(medusa_l1_hooks, ARRAY_SIZE(medusa_l1_hooks), "medusa");
	security_add_hooks(medusa_l1_hooks_alloc,
			   ARRAY_SIZE(medusa_l1_hooks_alloc), "medusa");
	med_pr_info("l1 registered with the kernel\n");

	return 0;
}

MODULE_LICENSE("GPL");

int medusa_enabled __ro_after_init = true;

struct lsm_blob_sizes medusa_blob_sizes __ro_after_init = {
	.lbs_cred = 0,
	.lbs_file = 0,
	.lbs_inode = sizeof(struct medusa_l1_inode_s),
	.lbs_superblock = 0,
	.lbs_ipc = sizeof(struct medusa_l1_ipc_s),
	.lbs_msg_msg = 0,
	.lbs_task = sizeof(struct medusa_l1_task_s),
};

DEFINE_LSM(medusa) = {
	.name = "medusa",
	.order = LSM_ORDER_MUTABLE,
	.flags = LSM_FLAG_LEGACY_MAJOR | LSM_FLAG_EXCLUSIVE,
	.enabled = &medusa_enabled,
	.init = medusa_l1_init,
	.blobs = &medusa_blob_sizes,
};

#endif /* CONFIG_SECURITY_MEDUSA */

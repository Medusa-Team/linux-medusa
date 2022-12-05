// SPDX-License-Identifier: GPL-2.0

#ifdef CONFIG_SECURITY_MEDUSA

#include <linux/binfmts.h>
#include <linux/module.h>
#include <linux/sched/task.h>

#include "l4/comm.h"
#include "l3/registry.h"
#include "l3/arch.h"
#include "l1/inode.h"
#include "l1/task.h"
#include "l1/ipc.h"
#include "l1/socket.h"
#include "l1/fuck.h"
#include "../../../../fs/mount.h" /* real_mount(), struct mount */

int medusa_l1_inode_alloc_security(struct inode *inode);

/*
 * static int medusa_l1_quotactl(int cmds, int type, int id, struct super_block *sb)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_quota_on(struct dentry *dentry)
 * {
 *	return 0;
 * }
 */

static int medusa_l1_creds_for_exec(struct linux_binprm *bprm)
{
	if (medusa_exec(bprm) == MED_DENY)
		return -EACCES;
	return 0;
}

/*
 * static int medusa_l1_bprm_check_security (struct linux_binprm *bprm)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_bprm_committing_creds(struct linux_binprm *bprm)
 * {
 * }
 */

/*
 * static void medusa_l1_bprm_committed_creds(struct linux_binprm *bprm)
 * {
 * }
 */

/*
 * static int medusa_l1_sb_alloc_security(struct super_block *sb)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_sb_free_security(struct super_block *sb)
 * {
 * }
 */

/*
 * static int medusa_l1_sb_remount(struct super_block *sb, void *data)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_sb_kern_mount(struct super_block *sb)
 * {
 *	struct inode *inode = sb->s_root->d_inode;
 *
 *	if (inode->i_security == NULL) {
 *		med_pr_warn("WARNING: l1_sb_kern_mount_inode->i_security is NULL");
 *		return medusa_l1_inode_alloc_security(inode);
 *	}
 *
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_sb_show_options(struct seq_file *m, struct super_block *sb)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_sb_statfs(struct dentry *dentry)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_sb_mount(const char *dev_name, const struct path *path, const char *type,
 *			unsigned long flags, void *data)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_sb_umount(struct vfsmount *mnt, int flags)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_sb_pivotroot(const struct path *old_path, const struct path *new_path)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_sb_set_mnt_opts(struct super_block *sb,
 *				void *opts,
 *								unsigned long kern_flags,
 *								unsigned long *set_kern_flags)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_sb_clone_mnt_opts(const struct super_block *oldsb,
 *				struct super_block *newsb)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_dentry_init_security(struct dentry *dentry, int mode,
 *					const struct qstr *name, void **ctx, u32 *ctxlen)
 * {
 *	if (dentry->d_inode != NULL) {
 *		if (dentry->d_inode->i_security == NULL) {
 *			med_pr_warn("WARNING l1_dentry_init_security dentry->d_inode->i_security is NULL");
 *			return medusa_l1_inode_alloc_security(dentry->d_inode);
 *		}
 *
 *	}
 *	// TODO: why return -EOPNOTSUPP ?
 *	return -EOPNOTSUPP;
 * }
 */

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
	init_med_object(&(med->med_object));

	return 0;
}

void medusa_l1_inode_free_security(struct inode *inode)
{
	struct medusa_l1_inode_s *med = inode_security(inode);

	if (unlikely(med && !hash_empty(med->fuck)))
		fuck_free(med);
}

/*
 * static int medusa_l1_inode_init_security(
 *	struct inode *inode,
 *	struct inode *dir,
 *	const struct qstr *qstr, const char **name,
 *	void **value, size_t *len)
 * {
 */
	/*
	 * Returns 0 if @name and @value have been successfully set,
	 * -EOPNOTSUPP if no security attribute is needed, or
	 * -ENOMEM on memory allocation failure.
	 *
	 * For details see include/linux/lsm_hooks.
	 */
/*
 *	return -EOPNOTSUPP;
 * }
 */

static int medusa_l1_inode_create(struct inode *inode, struct dentry *dentry,
				  umode_t mode)
{
	if (medusa_create(dentry, mode) == MED_DENY)
		return -EACCES;

	return 0;
}

static int medusa_l1_inode_link(struct dentry *old_dentry, struct inode *inode,
				struct dentry *new_dentry)
{
	/* if (medusa_link(old_dentry, new_dentry->d_name.name) == MED_DENY) */
		/* return -EACCES; */

	return 0;
}

static int medusa_l1_inode_unlink(struct inode *inode, struct dentry *dentry)
{
	//if (medusa_unlink(dentry) == MED_DENY)
	//	return -EACCES;

	return 0;
}

static int medusa_l1_inode_symlink(struct inode *inode, struct dentry *dentry,
				   const char *name)
{
	/* if (medusa_symlink(dentry, name) == MED_DENY) */
		/* return -EACCES; */

	return 0;
}

static int medusa_l1_inode_mkdir(struct inode *inode, struct dentry *dentry,
				 umode_t mask)
{
	//if(medusa_mkdir(dentry, mask) == MED_DENY)
	//	return -EACCES;

	return 0;
}

static int medusa_l1_inode_rmdir(struct inode *inode, struct dentry *dentry)
{
	//if (medusa_rmdir(dentry) == MED_DENY)
	//	return -EACCES;

	return 0;
}

static int medusa_l1_inode_mknod(struct inode *inode, struct dentry *dentry,
				 umode_t mode, dev_t dev)
{
	/* if (medusa_mknod(dentry, dev, mode) == MED_DENY) */
		/* return -EACCES; */
	return 0;
}

static int medusa_l1_inode_rename(struct inode *old_inode,
				  struct dentry *old_dentry,
				  struct inode *new_inode,
				  struct dentry *new_dentry)
{
	//if (medusa_rename(old_dentry, new_dentry->d_name.name) == MED_DENY)
	//	return -EACCES;
	return 0;
}

static int medusa_l1_inode_readlink(struct dentry *dentry)
{
	if (medusa_readlink(dentry) == MED_DENY)
		return -EACCES;
	return 0;
}

static int medusa_l1_inode_follow_link(struct dentry *dentry,
				       struct inode *inode,
				       bool rcu)
{
	return 0;
}

static int medusa_l1_inode_permission(struct inode *inode, int mask)
{
	int no_block = mask & MAY_NOT_BLOCK;

	if (no_block)
		return -ECHILD;

	mask &= (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);
	/*
	 * Existence test.
	 * TODO What about Medusa SEE permission?
	 */
	if (mask == 0)
		return 0;

	if (medusa_permission(inode, mask) == MED_DENY)
		return -EACCES;
	return 0;
}

/*
 * static int medusa_l1_inode_setattr(struct dentry *dentry, struct iattr *iattr)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_inode_getattr(const struct path* path)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_inode_post_setxattr(
 *	struct dentry *dentry,
 *	const char *name,
 *	const void *value, size_t size, int flags)
 * {
 * }
 */

/*
 * static int medusa_l1_inode_getxattr(struct dentry *dentry, const char *name)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_inode_listxattr(struct dentry *dentry)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_inode_setsecurity(struct inode *inode, const char *name,
 *				 const void *value, size_t size, int flags)
 * {
 *	return -EOPNOTSUPP;
 * }
 */

/*
 * static int medusa_l1_inode_listsecurity(struct inode *inode, char *buffer,
 *				size_t buffer_size)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_inode_getsecid(struct inode *inode, u32 *secid)
 * {
 *	*secid = 0;
 * }
 */

#ifdef CONFIG_SECURITY_PATH

static int medusa_l1_path_mknod(const struct path *dir, struct dentry *dentry,
				umode_t mode, unsigned int dev)
{
	if(medusa_mknod(dir, dentry, mode, dev) == MED_DENY)
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

/*
 * static int medusa_l1_file_permission(struct file *file, int mask)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_file_alloc_security(struct file *file)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_file_free_security(struct file *file)
 * {
 * }
 */

/*
 * static int medusa_l1_file_ioctl(struct file *file, unsigned int command,
 *			unsigned long arg)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
 *				 unsigned long prot)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_file_lock(struct file *file, unsigned int cmd)
 * {
 *	return 0;
 * }
 */

static int medusa_l1_file_fcntl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	if (medusa_fcntl(file, cmd, arg) == MED_DENY)
		return -EACCES;
	return 0;
}

/*
 * static void medusa_l1_file_set_fowner(struct file *file)
 * {
 *	return;
 * }
 */

/*
 * static int medusa_l1_file_send_sigiotask(struct task_struct *tsk,
 *				struct fown_struct *fown, int sig)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_file_receive(struct file *file)
 * {
 *	return 0;
 * }
 */

static int medusa_l1_file_open(struct file *file)
{
	if (medusa_open(file) == MED_DENY)
		return -EACCES;
	//return validate_fuck(&file->f_path);
	return 0;
}

/*
 * Function security_task_alloc() is called only from fork().
 * If there is no memory for security blob allocation, -ENOMEM is returned
 * to fork(). Invariant: each task *must have* a task security blob
 * allocated, if its size is not zero. Implication: no checks for Medusa's
 * task security blob are required.
 */
int medusa_l1_task_init(struct task_struct *task, unsigned long clone_flags)
{
	struct medusa_l1_task_s *med = task_security(task);

	init_med_object(&(med->med_object));
	init_med_subject(&(med->med_subject));

	mutex_init(&(med->validation_in_progress));
	med->validation_depth_nesting = 1;

#ifndef CONFIG_SECURITY_MEDUSA_MONITOR_KTHREADS
	/* Kernel threads have a superpower... Don't try to restrict them! */
	if ((task->flags & PF_KTHREAD) || !task->mm)
		med_magic_not_monitored(&med->med_object);
#endif
#ifdef CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL
	med->self = NULL;
	refcount_set(&med->rcu_cb_set, 0);
#endif /* CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILLCONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL */

	return 0;
}

void medusa_l1_task_free(struct task_struct *task)
{
}

/*
 * static int medusa_l1_cred_alloc_blank(struct cred *cred, gfp_t gfp)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_cred_free(struct cred *cred)
 * {
 * }
 */

/*
 * static int medusa_l1_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_cred_transfer(struct cred *new, const struct cred *old)
 * {
 * }
 */

/*
 * static void medusa_l1_cred_getsecid(const struct cred *c, u32 *secid)
 * {
 * }
 */

/*
 * static int medusa_l1_kernel_act_as(struct cred *new, u32 secid)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_kernel_create_files_as(struct cred *new, struct inode *inode)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_kernel_module_request(char *kmod_name)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_task_setpgid(struct task_struct *p, pid_t pgid)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_task_getpgid(struct task_struct *p)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_task_getsid(struct task_struct *p)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_task_getsecid(struct task_struct *p, u32 *secid)
 * {
 *	*secid = 0;
 * }
 */

/*
 * static int medusa_l1_task_getioprio(struct task_struct *p)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_task_setrlimit(struct task_struct *p, unsigned int resource,
 *				 struct rlimit *new_rlim)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_task_getscheduler(struct task_struct *p)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_task_movememory(struct task_struct *p)
 * {
 *	return 0;
 * }
 */

#ifdef CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL
static int medusa_l1_task_kill(struct task_struct *p, struct kernel_siginfo *info,
			       int sig, const struct cred *cred)
{
	if (medusa_sendsig(p, info, sig, cred) == MED_DENY)
		return -EACCES;

	return 0;
}
#endif /* CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL */

/*
 * static void medusa_l1_task_to_inode(struct task_struct *p, struct inode *inode)
 * {
 * }
 */

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

	init_med_object(&(med->med_object));
	med->ipc_class = ipc_class;
	return 0;
}

/*
 * static void medusa_l1_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
 * {
 *	*secid = 0;
 * }
 */

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

#ifdef CONFIG_SECURITY_NETWORK

/*
 * static int medusa_l1_unix_stream_connect(struct sock *sock, struct sock *other,
 *				struct sock *newsk)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_unix_may_send(struct socket *sock, struct socket *other)
 * {
 *	return 0;
 * }
 */

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
 * static int medusa_l1_socket_getsockname(struct socket *sock)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_getpeername(struct socket *sock)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_setsockopt(struct socket *sock, int level, int optname)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_getsockopt(struct socket *sock, int level, int optname)
 * {
 *	return 0;
 * }
 */

/*
 *static int medusa_l1_socket_shutdown(struct socket *sock, int how)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_getpeersec_stream(struct socket *sock,
 *					char __user *optval,
 *					int __user *optlen, unsigned len)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_socket_getpeersec_dgram(struct socket *sock,
 *					struct sk_buff *skb, u32 *secid)
 * {
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

/*
 * static void medusa_l1_sk_getsecid(struct sock *sk, u32 *secid)
 * {
 * }
 */

/*
 * static void medusa_l1_sock_graft(struct sock *sk, struct socket *parent)
 * {
 * }
 */

/*
 * static int medusa_l1_inet_conn_request(struct sock *sk, struct sk_buff *skb,
 *				 struct request_sock *req)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_inet_csk_clone(struct sock *newsk,
 *				const struct request_sock *req)
 * {
 * }
 */

/*
 * static void medusa_l1_inet_conn_established(struct sock *sk, struct sk_buff *skb)
 * {
 * }
 */

/*
 * static int medusa_l1_secmark_relabel_packet(u32 secid)
 * {
 *		return 0;
 * }
 */

/*
 * static void medusa_l1_secmark_refcount_inc(void)
 * {
 * }
 */

/*
 * static void medusa_l1_secmark_refcount_dec(void)
 * {
 * }
 */

/*
 * static void medusa_l1_req_classify_flow(const struct request_sock *req,
 *				struct flowi *fl)
 * {
 * }
 */

/*
 * static int medusa_l1_tun_dev_alloc_security(void **security)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_tun_dev_free_security(void *security)
 * {
 * }
 */

/*
 * static int medusa_l1_tun_dev_create(void)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_tun_dev_attach_queue(void *security)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_tun_dev_attach(struct sock *sk, void* security)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_tun_dev_open(void *security)
 * {
 *	return 0;
 * }
 */

#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM

/*
 * static int medusa_l1_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp,
 *										struct xfrm_user_sec_ctx *sec_ctx,
 *										gfp_t gfp)
 *
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_xfrm_policy_clone(struct xfrm_sec_ctx *old_ctx,
 *					struct xfrm_sec_ctx **new_ctxp)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_xfrm_policy_free(struct xfrm_sec_ctx *ctx)
 * {
 * }
 */

/*
 * static int medusa_l1_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_xfrm_state_alloc(struct xfrm_state *x,
 *					 struct xfrm_user_sec_ctx *sec_ctx)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_xfrm_state_alloc_acquire(struct xfrm_state *x,
 *					 struct xfrm_sec_ctx *polsec,
 *					 u32 secid)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_xfrm_state_free(struct xfrm_state *x)
 * {
 * }
 */

/*
 * static int medusa_l1_xfrm_state_delete(struct xfrm_state *x)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 sk_sid, u8 dir)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_xfrm_state_pol_flow_match(struct xfrm_state *x,
 *					 struct xfrm_policy *xp,
 *					 const struct flowi *fl)
 * {
 *	return 1;
 * }
 */

/*
 * static int medusa_l1_xfrm_decode_session(struct sk_buff *skb, u32 *fl, int ckall)
 * {
 *	return 0;
 * }
 */

#endif /* CONFIG_SECURITY_NETWORK_XFRM */

/*
 * static void medusa_l1_d_instantiate(struct dentry *dentry, struct inode *inode)
 * {
 * }
 */

/*
 * static int medusa_l1_getprocattr(struct task_struct *p, char *name, char **value)
 * {
 *	return -EINVAL;
 * }
 */

/*
 * static int medusa_l1_setprocattr(const char *name, void *value,
 *			size_t size)
 * {
 *	return -EINVAL;
 * }
 */

/*
 * static int medusa_l1_ismaclabel(const char *name)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
 * {
 *	return -EOPNOTSUPP;
 * }
 */

/*
 * static int medusa_l1_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
 * {
 *	return -EOPNOTSUPP;
 * }
 */

/*
 * static void medusa_l1_release_secctx(char *secdata, u32 seclen)
 * {
 * }
 */

/*
 * static int medusa_l1_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
 * {
 *	return -EOPNOTSUPP;
 * }
 */

/*
 * static int medusa_l1_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
 * {
 *	return -EOPNOTSUPP;
 * }
 */

/*
 * static int medusa_l1_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
 * {
 *	return -EOPNOTSUPP;
 * }
 */

#ifdef CONFIG_KEYS

/*
 * static int medusa_l1_key_alloc(struct key *key, const struct cred *cred,
 *			 unsigned long flags)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_key_free(struct key *key)
 * {
 * }
 */

/*
 * static int medusa_l1_key_permission(key_ref_t key_ref, const struct cred *cred,
 *				key_perm_t perm)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_key_getsecurity(struct key *key, char **_buffer)
 * {
 *	*_buffer = NULL;
 *	return 0;
 * }
 */

#endif /* CONFIG_KEYS */

#ifdef CONFIG_AUDIT

/*
 * static int medusa_l1_audit_rule_init(u32 field, u32 op, char *rulestr, void **lsmrule)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_audit_rule_known(struct audit_krule *krule)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule)
 * {
 *	return 0;
 * }
 */

/*
 * static void medusa_l1_audit_rule_free(void *lsmrule)
 * {
 * }
 */

#endif /* CONFIG_AUDIT */

/*
 * static int medusa_l1_syslog(int type)
 * {
 *	return 0;
 * }
 */

/*
 * static int medusa_l1_netlink_send(struct sock *sk, struct sk_buff *skb)
 * {
 *	return 0;
 * }
 */

static int medusa_l1_inode_setxattr(struct dentry *dentry, const char *name,
				    const void *value, size_t size, int flags)
{
	return cap_inode_setxattr(dentry, name, value, size, flags);
}


static int medusa_l1_inode_removexattr(struct user_namespace *mnt_userns,
				       struct dentry *dentry, const char *name)
{
	return cap_inode_removexattr(mnt_userns, dentry, name);
}

static struct security_hook_list medusa_l1_hooks[] = {
	//LSM_HOOK_INIT(binder_set_context_mgr, medusa_l1_binder_set_context_mgr),
	//LSM_HOOK_INIT(binder_transaction, medusa_l1_binder_transaction),
	//LSM_HOOK_INIT(binder_transfer_binder, medusa_l1_binder_transfer_binder),
	//LSM_HOOK_INIT(binder_transfer_file, medusa_l1_binder_transfer_file,),

	//LSM_HOOK_INIT(ptrace_access_check, medusa_l1_ptrace_access_check),
	//LSM_HOOK_INIT(ptrace_traceme, medusa_l1_ptrace_traceme),
	//LSM_HOOK_INIT(capget, medusa_l1_capget),
	//LSM_HOOK_INIT(capset, medusa_l1_capset),
	//LSM_HOOK_INIT(capable, medusa_l1_capable),
	//LSM_HOOK_INIT(quotactl, medusa_l1_quotactl),
	//LSM_HOOK_INIT(quota_on, medusa_l1_quota_on),
	//LSM_HOOK_INIT(syslog, medusa_l1_syslog),
	//LSM_HOOK_INIT(settime, medusa_l1_settime),
	//LSM_HOOK_INIT(vm_enough_memory, medusa_l1_vm_enough_memory),

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

	/* Needed for inode based security check */
	//LSM_HOOK_INIT(path_notify, medusa_l1_path_notify),
	//LSM_HOOK_INIT(inode_init_security, medusa_l1_inode_init_security),
	//LSM_HOOK_INIT(inode_init_security_anon, medusa_l1_inode_init_security_anon),
	//LSM_HOOK_INIT(inode_create, medusa_l1_inode_create),
	//LSM_HOOK_INIT(inode_link, medusa_l1_inode_link),
	//LSM_HOOK_INIT(inode_unlink, medusa_l1_inode_unlink),
	//LSM_HOOK_INIT(inode_symlink, medusa_l1_inode_symlink),
	//LSM_HOOK_INIT(inode_mkdir, medusa_l1_inode_mkdir),
	//LSM_HOOK_INIT(inode_rmdir, medusa_l1_inode_rmdir),
	//LSM_HOOK_INIT(inode_mknod, medusa_l1_inode_mknod),
	//LSM_HOOK_INIT(inode_rename, medusa_l1_inode_rename),
	//LSM_HOOK_INIT(inode_readlink, medusa_l1_inode_readlink),
	//LSM_HOOK_INIT(inode_follow_link, medusa_l1_inode_follow_link),
	//LSM_HOOK_INIT(inode_permission, medusa_l1_inode_permission),
	//LSM_HOOK_INIT(inode_setattr, medusa_l1_inode_setattr),
	//LSM_HOOK_INIT(inode_getattr, medusa_l1_inode_getattr),
	//LSM_HOOK_INIT(inode_setxattr, medusa_l1_inode_setxattr),
	//LSM_HOOK_INIT(inode_post_setxattr, medusa_l1_inode_post_setxattr),
	//LSM_HOOK_INIT(inode_getxattr, medusa_l1_inode_getxattr),
	//LSM_HOOK_INIT(inode_listxattr, medusa_l1_inode_listxattr),
	//LSM_HOOK_INIT(inode_removexattr, medusa_l1_inode_removexattr),
	//LSM_HOOK_INIT(inode_need_killpriv, medusa_l1_inode_need_killpriv),
	//LSM_HOOK_INIT(inode_killpriv, medusa_l1_inode_killpriv),
	//LSM_HOOK_INIT(inode_getsecurity, medusa_l1_inode_getsecurity),
	//LSM_HOOK_INIT(inode_setsecurity, medusa_l1_inode_setsecurity),
	//LSM_HOOK_INIT(inode_listsecurity, medusa_l1_inode_listsecurity),
	//LSM_HOOK_INIT(inode_getsecid, medusa_l1_inode_getsecid),
	//LSM_HOOK_INIT(inode_copy_up, medusa_l1_inode_copy_up),
	//LSM_HOOK_INIT(inode_copy_up_xattr, medusa_l1_inode_copy_up_xattr),

	//LSM_HOOK_INIT(kernfs_init_security, medusa_l1_kernfs_init_security),

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
	//LSM_HOOK_INIT(task_fix_setuid, medusa_l1_task_fix_setuid),
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
	LSM_HOOK_INIT(msg_queue_associate, medusa_ipc_associate),
	LSM_HOOK_INIT(msg_queue_msgctl, medusa_ipc_ctl),
	LSM_HOOK_INIT(msg_queue_msgsnd, medusa_ipc_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv, medusa_ipc_msgrcv),
	LSM_HOOK_INIT(shm_associate, medusa_ipc_associate),
	LSM_HOOK_INIT(shm_shmctl, medusa_ipc_ctl),
	LSM_HOOK_INIT(shm_shmat, medusa_ipc_shmat),
	LSM_HOOK_INIT(sem_associate, medusa_ipc_associate),
	LSM_HOOK_INIT(sem_semctl, medusa_ipc_ctl),
	LSM_HOOK_INIT(sem_semop, medusa_ipc_semop),

	//LSM_HOOK_INIT(netlink_send, medusa_l1_netlink_send),

	//LSM_HOOK_INIT(d_instantiate, medusa_l1_d_instantiate),

	//LSM_HOOK_INIT(getprocattr, medusa_l1_getprocattr),
	//LSM_HOOK_INIT(setprocattr, medusa_l1_setprocattr),

	//LSM_HOOK_INIT(ismaclabel, medusa_l1_ismaclabel),

	//LSM_HOOK_INIT(secid_to_secctx, medusa_l1_secid_to_secctx),
	//LSM_HOOK_INIT(secctx_to_secid, medusa_l1_secctx_to_secid),
	//LSM_HOOK_INIT(release_secctx, medusa_l1_release_secctx),

	//LSM_HOOK_INIT(inode_invalidate_secctx, medusa_l1_inode_invalidate_secctx),
	//LSM_HOOK_INIT(inode_notifysecctx, medusa_l1_inode_notifysecctx),
	//LSM_HOOK_INIT(inode_setsecctx, medusa_l1_inode_setsecctx),
	//LSM_HOOK_INIT(inode_getsecctx, medusa_l1_inode_getsecctx),

#if defined(CONFIG_SECURITY) && defined(CONFIG_WATCH_QUEUE)
	//LSM_HOOK_INIT(post_notification, medusa_l1_post_notification),
#endif /* CONFIG_SECURITY && CONFIG_WATCH_QUEUE */

#if defined(CONFIG_SECURITY) && defined(CONFIG_KEY_NOTIFICATIONS)
	//LSM_HOOK_INIT(watch_key, medusa_l1_watch_key),
#endif /* CONFIG_SECURITY && CONFIG_KEY_NOTIFICATIONS */

#ifdef CONFIG_SECURITY_NETWORK
	/*
	 * LSM_HOOK_INIT(unix_stream_connect, medusa_l1_unix_stream_connect),
	 * LSM_HOOK_INIT(unix_may_send, medusa_l1_unix_may_send),

	 * LSM_HOOK_INIT(socket_create, medusa_l1_socket_create),
	 * LSM_HOOK_INIT(socket_post_create, medusa_l1_socket_post_create),
	 * LSM_HOOK_INIT(socket_socketpair, medusa_l1_socket_socketpair),
	 * LSM_HOOK_INIT(socket_bind, medusa_l1_socket_bind),
	 * LSM_HOOK_INIT(socket_connect, medusa_l1_socket_connect),
	 * LSM_HOOK_INIT(socket_listen, medusa_l1_socket_listen),
	 * LSM_HOOK_INIT(socket_accept, medusa_l1_socket_accept),
	 * LSM_HOOK_INIT(socket_sendmsg, medusa_l1_socket_sendmsg),
	 * LSM_HOOK_INIT(socket_recvmsg, medusa_l1_socket_recvmsg),
	 * LSM_HOOK_INIT(socket_getsockname, medusa_l1_socket_getsockname),
	 * LSM_HOOK_INIT(socket_getpeername, medusa_l1_socket_getpeername),
	 * LSM_HOOK_INIT(socket_getsockopt, medusa_l1_socket_getsockopt),
	 * LSM_HOOK_INIT(socket_setsockopt, medusa_l1_socket_setsockopt),
	 * LSM_HOOK_INIT(socket_shutdown, medusa_l1_socket_shutdown),
	 * LSM_HOOK_INIT(socket_sock_rcv_skb, medusa_l1_socket_sock_rcv_skb),
	 * LSM_HOOK_INIT(socket_getpeersec_stream, medusa_l1_socket_getpeersec_stream),
	 * LSM_HOOK_INIT(socket_getpeersec_dgram, medusa_l1_socket_getpeersec_dgram),
	 * LSM_HOOK_INIT(sk_alloc_security, medusa_l1_sk_alloc_security),
	 * LSM_HOOK_INIT(sk_free_security, medusa_l1_sk_free_security),
	 * LSM_HOOK_INIT(sk_clone_security, medusa_l1_sk_clone_security),
	 * LSM_HOOK_INIT(sk_getsecid, medusa_l1_sk_getsecid),
	 * LSM_HOOK_INIT(sock_graft, medusa_l1_sock_graft),
	 * LSM_HOOK_INIT(inet_conn_request, medusa_l1_inet_conn_request),
	 * LSM_HOOK_INIT(inet_csk_clone, medusa_l1_inet_csk_clone),
	 * LSM_HOOK_INIT(inet_conn_established, medusa_l1_inet_conn_established),
	 * LSM_HOOK_INIT(secmark_relabel_packet, medusa_l1_secmark_relabel_packet),
	 * LSM_HOOK_INIT(secmark_refcount_inc, medusa_l1_secmark_refcount_inc),
	 * LSM_HOOK_INIT(secmark_refcount_dec, medusa_l1_secmark_refcount_dec),
	 * LSM_HOOK_INIT(req_classify_flow, medusa_l1_req_classify_flow),
	 * LSM_HOOK_INIT(tun_dev_alloc_security, medusa_l1_tun_dev_alloc_security),
	 * LSM_HOOK_INIT(tun_dev_free_security, medusa_l1_tun_dev_free_security),
	 * LSM_HOOK_INIT(tun_dev_create, medusa_l1_tun_dev_create),
	 * LSM_HOOK_INIT(tun_dev_attach_queue, medusa_l1_tun_dev_attach_queue),
	 * LSM_HOOK_INIT(tun_dev_attach, medusa_l1_tun_dev_attach),
	 * LSM_HOOK_INIT(tun_dev_open, medusa_l1_tun_dev_open),
	 * LSM_HOOK_INIT(sctp_assoc_request, medusa_l1_sctp_assoc_request),
	 * LSM_HOOK_INIT(sctp_bind_connect, medusa_l1_sctp_bind_connect),
	 * LSM_HOOK_INIT(sctp_sk_clone, medusa_l1_sctp_sk_clone),
	 */
#endif /* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_INFINIBAND
	//LSM_HOOK_INIT(ib_pkey_access, medusa_l1_ib_pkey_access),
	//LSM_HOOK_INIT(ib_endport_manage_subnet, medusa_l1_ib_endport_manage_subnet),
	//LSM_HOOK_INIT(ib_alloc_security, medusa_l1_ib_alloc_security),
	//LSM_HOOK_INIT(ib_free_security, medusa_l1_ib_free_security),
#endif /* CONFIG_SECURITY_INFINIBAND */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
	/*
	 * LSM_HOOK_INIT(xfrm_policy_alloc_security, medusa_l1_xfrm_policy_alloc),
	 * LSM_HOOK_INIT(xfrm_policy_clone_security, medusa_l1_xfrm_policy_clone),
	 * LSM_HOOK_INIT(xfrm_policy_free_security, medusa_l1_xfrm_policy_free),
	 * LSM_HOOK_INIT(xfrm_policy_delete_security, medusa_l1_xfrm_policy_delete),
	 * LSM_HOOK_INIT(xfrm_state_alloc, medusa_l1_xfrm_state_alloc),
	 * LSM_HOOK_INIT(xfrm_state_alloc_acquire, medusa_l1_xfrm_state_alloc_acquire),
	 * LSM_HOOK_INIT(xfrm_state_free_security, medusa_l1_xfrm_state_free),
	 * LSM_HOOK_INIT(xfrm_state_delete_security, medusa_l1_xfrm_state_delete),
	 * LSM_HOOK_INIT(xfrm_policy_lookup, medusa_l1_xfrm_policy_lookup),
	 * LSM_HOOK_INIT(xfrm_state_pol_flow_match, medusa_l1_xfrm_state_pol_flow_match),
	 * LSM_HOOK_INIT(xfrm_decode_session, medusa_l1_xfrm_decode_session),
	 */
#endif /* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_KEYS
	/*
	 * LSM_HOOK_INIT(key_alloc, medusa_l1_key_alloc),
	 * LSM_HOOK_INIT(key_free, medusa_l1_key_free),
	 * LSM_HOOK_INIT(key_permission, medusa_l1_key_permission),
	 * LSM_HOOK_INIT(key_getsecurity, medusa_l1_key_getsecurity),
	 */
#endif /* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
	/*
	 * LSM_HOOK_INIT(audit_rule_init, medusa_l1_audit_rule_init),
	 * LSM_HOOK_INIT(audit_rule_known, medusa_l1_audit_rule_known),
	 * LSM_HOOK_INIT(audit_rule_match, medusa_l1_audit_rule_match),
	 * LSM_HOOK_INIT(audit_rule_free, medusa_l1_audit_rule_free),
	 */
#endif /* CONFIG_AUDIT */

#ifdef CONFIG_BPF_SYSCALL
	//LSM_HOOK_INIT(bpf, medusa_l1_bpf),
	//LSM_HOOK_INIT(bpf_map, medusa_l1_bpf_map),
	//LSM_HOOK_INIT(bpf_prog, medusa_l1_bpf_prog),
	//LSM_HOOK_INIT(bpf_map_alloc_security, medusa_l1_bpf_map_alloc_security),
	//LSM_HOOK_INIT(bpf_map_free_security, medusa_l1_bpf_map_free_security),
	//LSM_HOOK_INIT(bpf_prog_alloc_security, medusa_l1_bpf_prog_alloc_security),
	//LSM_HOOK_INIT(bpf_prog_free_security, medusa_l1_bpf_prog_free_security),
#endif /* CONFIG_BPF_SYSCALL */

	//LSM_HOOK_INIT(locked_down, medusa_l1_locked_down),

#ifdef CONFIG_PERF_EVENTS
	//LSM_HOOK_INIT(perf_event_open, medusa_l1_perf_event_open),
	//LSM_HOOK_INIT(perf_event_alloc, medusa_l1_perf_event_alloc),
	//LSM_HOOK_INIT(perf_event_free, medusa_l1_perf_event_free),
	//LSM_HOOK_INIT(perf_event_read, medusa_l1_perf_event_read),
	//LSM_HOOK_INIT(perf_event_write, medusa_l1_perf_event_write),
#endif /* CONFIG_PERF_EVENTS */

#ifdef CONFIG_IO_URING
	//LSM_HOOK_INIT(uring_override_creds, medusa_l1_uring_override_creds),
	//LSM_HOOK_INIT(uring_sqpoll, medusa_l1_uring_sqpoll),
#endif /* CONFIG_IO_URING */
};

struct security_hook_list medusa_l1_hooks_alloc[] = {
	LSM_HOOK_INIT(task_alloc, medusa_l1_task_init),
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
	medusa_l1_task_init(current, 0);

	/* register the hooks */
	security_add_hooks(medusa_l1_hooks, ARRAY_SIZE(medusa_l1_hooks), "medusa");
	security_add_hooks(medusa_l1_hooks_alloc,
			   ARRAY_SIZE(medusa_l1_hooks_alloc), "medusa");
	med_pr_info("l1 registered with the kernel\n");

	/*
	 * TODO TODO TODO
	 *
	 * during initialization process of security struct
	 * there has no sence to call acctypes on l2 layer (auth server
	 * may not be connected)
	 * call only validation of security struct!
	 * (review also inodes, processes and IPC objects initialization
	 * from l0 lists)
	 */

	return 0;
}

static void __exit medusa_l1_exit(void)
{
	med_pr_info("medusa unload");
	//security_delete_hooks(medusa_hooks, ARRAY_SIZE(medusa_hooks));
}

MODULE_LICENSE("GPL");

/*
 * TODO: Refactor L1 using this variable (initialization).
 */
int medusa_enabled __lsm_ro_after_init = true;

struct lsm_blob_sizes medusa_blob_sizes __lsm_ro_after_init = {
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

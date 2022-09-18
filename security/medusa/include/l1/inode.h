/* SPDX-License-Identifier: GPL-2.0 */

/* (C) 2002 Milan Pikula
 *
 * struct inode extension: this structure is appended to in-kernel data,
 * and we define it separately just to make l1 code shorter.
 *
 * for another data structure - kobject, describing inode for upper layers -
 * see l2/kobject_file.[ch].
 */

#ifndef _MEDUSA_L1_INODE_H
#define _MEDUSA_L1_INODE_H

#include <linux/capability.h>
#include <linux/hashtable.h>
#include <linux/lsm_hooks.h>
#include "l3/med_model.h"
#include "l3/constants.h"

/* prototypes of L2 file related handlers called from L1 hooks */

extern enum medusa_answer_t medusa_exec(struct linux_binprm *bprm);
extern enum medusa_answer_t medusa_create(struct dentry *dentry, int mode);
extern enum medusa_answer_t medusa_lookup(struct inode *dir, struct dentry **dentry);
extern enum medusa_answer_t medusa_truncate(const struct path *path);
extern enum medusa_answer_t medusa_mkdir(const struct path *dir, struct dentry *dentry, int mode);
extern enum medusa_answer_t medusa_mknod(const struct path *dir,
					struct dentry *dentry, umode_t mode, unsigned int dev);
extern enum medusa_answer_t medusa_permission(struct inode *inode, int mask);
extern enum medusa_answer_t medusa_rmdir(const struct path *dir, struct dentry *dentry);
extern enum medusa_answer_t medusa_symlink(const struct path *dir, struct dentry *dentry, const char *oldname);
extern enum medusa_answer_t medusa_unlink(const struct path *dir, struct dentry *dentry);
extern enum medusa_answer_t medusa_link(struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry);
extern enum medusa_answer_t medusa_rename(const struct path *old_path, struct dentry *old_dentry,
					const struct path *new_path, struct dentry *new_dentry);
extern enum medusa_answer_t medusa_readlink(struct dentry *dentry);
extern enum medusa_answer_t medusa_chmod(const struct path *path, umode_t mode);
extern enum medusa_answer_t medusa_chown(const struct path *path, kuid_t uid, kgid_t gid);
extern enum medusa_answer_t medusa_chroot(const struct path *path);
extern enum medusa_answer_t medusa_fcntl(struct file *file, unsigned int cmd, unsigned long arg);
extern enum medusa_answer_t medusa_open(struct file *file);

/* the following routines are a support for many of access types,
 * and they're used both in L1 and L2 code. They're defined in
 * l2/evtype_getfile.c. Look there before using any of these routines.
 */

extern int file_kobj_validate_dentry(struct dentry *dentry, struct vfsmount *mnt, struct path *dir);
extern int file_kobj_validate_dentry_dir(const struct vfsmount *mnt, struct dentry *dentry);
extern void medusa_get_upper_and_parent(const struct path *ndsource, struct path *ndupperp, struct path *ndparentp);
extern void medusa_put_upper_and_parent(struct path *ndupper, struct path *ndparent);
extern struct vfsmount *medusa_evocate_mnt(struct dentry *dentry);
extern enum medusa_answer_t medusa_notify_change(struct dentry *dentry, struct iattr *attr);

extern enum medusa_answer_t medusa_read(struct file *file);
extern enum medusa_answer_t medusa_write(struct file *file);

/* Struct inode extension: this structure is appended to in-kernel data,
 * and we define it separately just to make l1 code shorter.
 */

extern struct lsm_blob_sizes medusa_blob_sizes;
#define inode_security(inode) ((struct medusa_l1_inode_s *)(inode->i_security + medusa_blob_sizes.lbs_inode))

struct medusa_l1_inode_s {
	struct medusa_object_s med_object;
	__u32 user;
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
	kernel_cap_t icap, pcap, ecap;  /* support for POSIX file capabilities */
#endif /* CONFIG_MEDUSA_FILE_CAPABILITIES */

	/* for kobject_file.c - don't touch! */
	struct inode *next_live;
	int use_count;
	DECLARE_HASHTABLE(fuck, 3); // enought for now; TODO add choice to menu config
};

#endif

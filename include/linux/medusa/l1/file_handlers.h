/* 
 * medusa/l1/file_handlers.h
 *
 * prototypes of L2 file related handlers called from L1 hooks
 *
 */

#ifndef _MEDUSA_L1_FILE_HANDLERS_H
#define _MEDUSA_L1_FILE_HANDLERS_H

//#include <linux/config.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/medusa/l3/constants.h>

extern medusa_answer_t medusa_exec(struct dentry ** dentryp);
extern medusa_answer_t medusa_create(struct dentry * dentry, int mode);
extern medusa_answer_t medusa_lookup(struct inode *dir, struct dentry **dentry);
extern medusa_answer_t medusa_truncate(struct dentry *dentry, unsigned long length);
extern medusa_answer_t medusa_mkdir(const struct path *parent, struct dentry *dentry, int mode);
extern medusa_answer_t medusa_mknod(struct dentry *dentry, dev_t dev, int mode);
extern medusa_answer_t medusa_permission(struct inode * inode, int mask);
extern medusa_answer_t medusa_rmdir(const struct path *dir, struct dentry *dentry);
extern medusa_answer_t medusa_symlink(struct dentry *dentry,
		const char * oldname);
extern medusa_answer_t medusa_unlink(struct dentry *dentry);
extern medusa_answer_t medusa_link(struct dentry *dentry, const char * newname);
extern medusa_answer_t medusa_rename(struct dentry *dentry, const char * newname);
extern medusa_answer_t medusa_readlink(struct dentry *dentry);
extern medusa_answer_t medusa_path_access(const char *action, char **path_to_redirect);

/* the following routines are a support for many of access types,
 * and they're used both in L1 and L2 code. They're defined in
 * l2/evtype_getfile.c. Look there before using any of these routines.
 */
extern int file_kobj_validate_dentry(struct dentry * dentry, struct vfsmount * mnt);
extern void medusa_get_upper_and_parent(struct path * ndsource,
		struct path * ndupperp, struct path * ndparentp);
extern void medusa_put_upper_and_parent(struct path * ndupper, struct path * ndparent);
extern struct vfsmount * medusa_evocate_mnt(struct dentry *dentry);
extern medusa_answer_t medusa_notify_change(struct dentry *dentry, struct iattr * attr);

extern medusa_answer_t medusa_read(struct file * file);
extern medusa_answer_t medusa_write(struct file * file);

/*
 * Following two functions are used by L1 code in case of acctype medusa_path_access().
 * medusa_get_path() converts struct path * to absolute path stored in buffer, which
 * may be released using medusa_put_path() function. Consult l2/acctype_path_access.c for
 * details.
 */
 extern char *medusa_get_path(const struct path *path, const struct qstr *last, int lasttype);
 extern void medusa_put_path(char **pathbuf);

#endif /* _MEDUSA_L1_FILE_HANDLERS_H */


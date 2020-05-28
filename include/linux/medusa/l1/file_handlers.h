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
 * Following two functions are used by L1 code in medusa_path_access().
 * medusa_get_path() converts struct path * to absolute path stored in buffer,
 * which may be released using medusa_put_path() function. Consult
 * l2/acctype_path_access.c for details.
 */
extern char *medusa_get_path(const struct path *path, const struct qstr *last, int lasttype);
extern void medusa_put_path(char **pathbuf);

// user_path_at() deals with __user char * pointer;
// path access on redirection (for simplicity and reusability of code) cannot be repeated
// with LOOKUP_REVAL flag, so this flag should be set immediately for the first
// attempt of path access
#define MEDUSA_PATH_ACCESS_PATHAT_FINI(path)					\
	how |= LOOKUP_REVAL;							\
	error = kern_path(path_to_redirect, LOOKUP_REVAL, &path)

// filename_parentat() uses struct filename @name; on redirection should be updated
#define MEDUSA_PATH_ACCESS_PARENTAT_FINI(name)					\
	putname(name);								\
	name = getname_kernel(path_to_redirect);				\
	medusa_redirected = 1

// filename_parentat() uses struct filename @name; on redirection should be updated
#define MEDUSA_PATH_ACCESS_CREATE_FINI(name)					\
	putname(name);								\
	name = getname_kernel(path_to_redirect)

/*
 * MEDUSA_PATH_ACCESS - L1 medusa path access code repeated in all use cases
 *
 * @acctype - path access description ("link", "rmdir", ...)
 * @path_ptr - pointer to path structure related to path in question
 * @last_ptr - pointer to qstr holding last element of path in question
 *	set only by filename_parentat() path loop call
 * @type - type of last element of path in question set only by filename_parentat()
 *	path loop call
 * @out - label of code branch to continue on error
 * @FINI - code to do on finish; it varies based on type of path loop:
 *	MEDUSA_PATH_ACCESS_PARENTAT_FINI - if filename_parentat() path loop is used
 *	MEDUSA_PATH_ACCESS_PATHAT_FINI - in case of user_path_at() path loop
 *
 * Notes: following variables are used in macro and therefore should be defined:
 *	- int @error for holding error code
 *	- medusa_allow code label to continue if no redirection is made
 *	- struct filename @name if MEDUSA_PATH_ACCESS_PARENTAT_FINI is used
 *	- flag int @medusa_redirected if MEDUSA_PATH_ACCESS_PARENTAT_FINI is used
 *	- flags int @how if MEDUSA_PATH_ACCESS_PATHAT_FINI is used
 */
#define MEDUSA_PATH_ACCESS(acctype, path_ptr, last_ptr, type, out, FINI)	\
{										\
		int res;							\
		char *path_to_redirect = NULL;					\
		path_to_redirect = medusa_get_path(path_ptr, last_ptr, type);	\
										\
		if (IS_ERR(path_to_redirect)) {					\
			error = PTR_ERR(path_to_redirect);			\
			goto out;						\
		}								\
		res = medusa_path_access(acctype, &path_to_redirect);		\
										\
		if (res == MED_DENY) {						\
			error = -EACCES;					\
			goto out;						\
		} else if (unlikely(res == MED_FAKE_ALLOW)) {			\
			error = 0;						\
			goto out;						\
		} else if (unlikely(path_to_redirect)) {			\
			path_put(path_ptr);					\
			FINI;							\
			medusa_put_path(&path_to_redirect);			\
		}								\
}

#endif /* _MEDUSA_L1_FILE_HANDLERS_H */

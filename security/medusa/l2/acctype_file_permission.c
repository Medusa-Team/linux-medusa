// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'file_permission' access type, with subj=task and obj=inode */

struct file_permission_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	int mask;
};

MED_ATTRS(file_permission_access) {
	MED_ATTR_RO(file_permission_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(file_permission_access, mask, "mask", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(file_permission_access, "file_permission", process_kobject, "process",
		file_kobject, "file");

int __init file_permission_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(file_permission_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

enum medusa_answer_t medusa_do_file_permission(struct path *path, int mask)
{
	struct file_permission_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	file_kobj_dentry2string_mnt(path, path->dentry, access.filename);
	access.mask = mask;
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, path->dentry->d_inode);
	file_kobj_live_add(path->dentry->d_inode);
	retval = MED_DECIDE(file_permission_access, &access, &process, &file);
	file_kobj_live_remove(path->dentry->d_inode);
	return retval;
}

/**
 * medusa_file_permission - L1-called code to create access of type 'file_permission'.
 * @file: contains the file structure being accessed.
 * @mask: contains the requested permissions (MAY_xxx).
 *
 */
enum medusa_answer_t medusa_file_permission(struct file *file, int mask)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct path *path = &file->f_path;
	struct dentry *dentry = path->dentry;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!dentry || IS_ERR(dentry)) {
		med_pr_warn("%s: invalid dentry for file %pD4", __func__, file);
		return retval;
	}
	/* TODO: Use file_inode or file_dentry()->d_inode? */
	if (!is_med_magic_valid(&(inode_security(dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry_dir(path->mnt, dentry) <= 0)
		return retval;
	if (
		!vs_intersects(VSS(task_security(current)), VS(inode_security(dentry->d_inode))) ||
		((mask & (MAY_EXEC | MAY_READ | MAY_ACCESS | MAY_OPEN)) &&
			!vs_intersects(VSR(task_security(current)), VS(inode_security(dentry->d_inode)))) ||
		((mask & (MAY_WRITE | MAY_APPEND) &&
			!vs_intersects(VSW(task_security(current)), VS(inode_security(dentry->d_inode)))))
	   ) {
		retval = MED_DENY;
		return retval;
	}

	if (MEDUSA_MONITORED_ACCESS_O(file_permission_access, inode_security(dentry->d_inode)))
		retval = medusa_do_file_permission(path, mask);
	return retval;
}

device_initcall(file_permission_acctype_init);

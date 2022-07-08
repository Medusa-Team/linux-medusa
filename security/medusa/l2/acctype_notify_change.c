// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'notify_change' access type, with subj=task and obj=inode */
/* todo: rename this to chmod or chattr or whatever */

struct notify_change_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	struct iattr attr;
	/* TODO: add few attributes here */
};

MED_ATTRS(notify_change_access) {
	MED_ATTR_RO(notify_change_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(notify_change_access, attr.ia_valid, "valid", MED_UNSIGNED),
	MED_ATTR(notify_change_access, attr.ia_mode, "mode", MED_UNSIGNED),
	MED_ATTR(notify_change_access, attr.ia_uid, "uid", MED_SIGNED),
	MED_ATTR(notify_change_access, attr.ia_gid, "gid", MED_SIGNED),
	MED_ATTR_RO(notify_change_access, attr.ia_size, "size", MED_UNSIGNED),
	MED_ATTR(notify_change_access, attr.ia_atime, "atime", MED_UNSIGNED),
	MED_ATTR(notify_change_access, attr.ia_mtime, "mtime", MED_UNSIGNED),
	MED_ATTR(notify_change_access, attr.ia_ctime, "ctime", MED_UNSIGNED),
	//MED_ATTR_RO(notify_change_access, attr.ia_attr_flags, "attr_flags", MED_BITMAP),
	MED_ATTR_END
};

MED_ACCTYPE(notify_change_access, "notify_change", process_kobject, "process",
		file_kobject, "file");

int __init notify_change_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(notify_change_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct notify_change_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	file_kobj_dentry2string(dentry, access.filename);
	access.attr.ia_valid = attr->ia_valid;
	access.attr.ia_mode = attr->ia_mode;
	access.attr.ia_uid = attr->ia_uid;
	access.attr.ia_gid = attr->ia_gid;
	access.attr.ia_size = attr->ia_size;
	access.attr.ia_atime = attr->ia_atime;
	access.attr.ia_mtime = attr->ia_mtime;
	access.attr.ia_ctime = attr->ia_ctime;
	//access.attr.ia_attr_flags = attr->ia_attr_flags;
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, dentry->d_inode);
	file_kobj_live_add(dentry->d_inode);
	retval = MED_DECIDE(notify_change_access, &access, &process, &file);
	file_kobj_live_remove(dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_notify_change(struct dentry *dentry, struct iattr *attr)
{
	if (!dentry || IS_ERR(dentry) || dentry->d_inode == NULL)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(inode_security(dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry(dentry, NULL, NULL) <= 0)
		return MED_ALLOW;

	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(dentry->d_inode)))
	)
		return MED_DENY;
	if (!attr)
		return MED_ALLOW;
	if (MEDUSA_MONITORED_ACCESS_O(notify_change_access, inode_security(dentry->d_inode)))
		return medusa_do_notify_change(dentry, attr);
	return MED_ALLOW;
}

device_initcall(notify_change_acctype_init);

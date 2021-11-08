// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'readlink' access type, with subj=task and obj=inode */

struct readlink_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
};

MED_ATTRS(readlink_access) {
	MED_ATTR_RO(readlink_access, filename, "filename", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(readlink_access, "readlink", process_kobject, "process",
		file_kobject, "file");

int __init readlink_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(readlink_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_readlink(struct dentry *dentry)
{
	struct readlink_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	file_kobj_dentry2string(dentry, access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, dentry->d_inode);
	file_kobj_live_add(dentry->d_inode);
	retval = MED_DECIDE(readlink_access, &access, &process, &file);
	file_kobj_live_remove(dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_readlink(struct dentry *dentry)
{
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
			process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;
	if (!is_med_magic_valid(&(inode_security(dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry(dentry, NULL, NULL) <= 0) {
		return MED_ALLOW;
	}
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(dentry->d_inode))) ||
			!vs_intersects(VSW(task_security(current)), VS(inode_security(dentry->d_inode)))
	   )
		return MED_DENY;
	if (MEDUSA_MONITORED_ACCESS_O(readlink_access, inode_security(dentry->d_inode)))
		return medusa_do_readlink(dentry);
	return MED_ALLOW;
}

device_initcall(readlink_acctype_init);

// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'truncate' access type, with subj=task and obj=inode */

struct truncate_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
};

MED_ATTRS(truncate_access) {
	MED_ATTR_RO(truncate_access, filename, "filename", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(truncate_access, "truncate", process_kobject, "process",
		file_kobject, "file");

int __init truncate_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(truncate_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_truncate(const struct path *path)
{
	struct truncate_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	file_kobj_dentry2string_mnt(path, path->dentry, access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, path->dentry->d_inode);
	file_kobj_live_add(path->dentry->d_inode);
	retval = MED_DECIDE(truncate_access, &access, &process, &file);
	file_kobj_live_remove(path->dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_truncate(const struct path *path)
{
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(inode_security(path->dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry_dir(path->mnt, path->dentry) <= 0)
		return MED_ALLOW;
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(path->dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(path->dentry->d_inode)))
	)
		return MED_DENY;
	if (MEDUSA_MONITORED_ACCESS_O(truncate_access, inode_security(path->dentry->d_inode)))
		return medusa_do_truncate(path);
	return MED_ALLOW;
}

device_initcall(truncate_acctype_init);

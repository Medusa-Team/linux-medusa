// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'mkdir' access type, with subj=task and obj=inode */

struct mkdir_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	int mode;
};

MED_ATTRS(mkdir_access) {
	MED_ATTR_RO(mkdir_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(mkdir_access, mode, "mode", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(mkdir_access, "mkdir", process_kobject, "process",
		file_kobject, "file");

int __init mkdir_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(mkdir_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_mkdir(const struct path *dir, struct dentry *dentry, int mode)
{
	struct mkdir_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	file_kobj_dentry2string_mnt(dir, dentry, access.filename);
	access.mode = mode;
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, dir->dentry->d_inode);
	file_kobj_live_add(dir->dentry->d_inode);
	retval = MED_DECIDE(mkdir_access, &access, &process, &file);
	file_kobj_live_remove(dir->dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_mkdir(const struct path *dir, struct dentry *dentry, int mode)
{
	struct path ndcurrent, ndupper;
	enum medusa_answer_t retval;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	ndcurrent = *dir;
	medusa_get_upper_and_parent(&ndcurrent, &ndupper, NULL);

	if (!is_med_magic_valid(&(inode_security(ndupper.dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry_dir(ndupper.mnt, ndupper.dentry) <= 0) {
		medusa_put_upper_and_parent(&ndupper, NULL);
		return MED_ALLOW;
	}
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(ndupper.dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(ndupper.dentry->d_inode)))
	) {
		medusa_put_upper_and_parent(&ndupper, NULL);
		return MED_DENY;
	}
	if (MEDUSA_MONITORED_ACCESS_O(mkdir_access, inode_security(ndupper.dentry->d_inode)))
		retval = medusa_do_mkdir(&ndupper, dentry, mode);
	else
		retval = MED_ALLOW;
	medusa_put_upper_and_parent(&ndupper, NULL);
	return retval;
}

device_initcall(mkdir_acctype_init);

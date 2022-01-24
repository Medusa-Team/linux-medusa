// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'symlink' access type, with subj=task and obj=inode */

struct symlink_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	char oldname[NAME_MAX+1]; /* hope we will fit in the stack. the string won't fit.. of course. */
};

MED_ATTRS(symlink_access) {
	MED_ATTR_RO(symlink_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(symlink_access, oldname, "oldname", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(symlink_access, "symlink", process_kobject, "process",
		file_kobject, "file");

int __init symlink_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(symlink_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_symlink(struct path *dir, struct dentry *dentry, const char *oldname)
{
	struct symlink_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;
	int oldnamelen;

	file_kobj_dentry2string_mnt(dir, dentry, access.filename);
	oldnamelen = strlen(oldname);
	if (oldnamelen > NAME_MAX)
		oldnamelen = NAME_MAX;
	memcpy(access.oldname, oldname, oldnamelen);
	access.oldname[oldnamelen] = '\0';
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, dir->dentry->d_inode);
	file_kobj_live_add(dir->dentry->d_inode);
	retval = MED_DECIDE(symlink_access, &access, &process, &file);
	file_kobj_live_remove(dir->dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_symlink(const struct path *dir, struct dentry *dentry, const char *oldname)
{
	struct path ndcurrent, ndupper;
	enum medusa_answer_t retval;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	ndcurrent = *dir;
	medusa_get_upper_and_parent(&ndcurrent, &ndupper, NULL);

	file_kobj_validate_dentry_dir(ndupper.mnt, ndupper.dentry);

	if (!is_med_magic_valid(&(inode_security(ndupper.dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry(ndupper.dentry, ndupper.mnt, NULL) <= 0) {
		medusa_put_upper_and_parent(&ndupper, NULL);
		return MED_ALLOW;
	}
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(ndupper.dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(ndupper.dentry->d_inode)))
	) {
		medusa_put_upper_and_parent(&ndupper, NULL);
		return MED_DENY;
	}
	if (MEDUSA_MONITORED_ACCESS_O(symlink_access, inode_security(ndupper.dentry->d_inode)))
		retval = medusa_do_symlink(&ndupper, dentry, oldname);
	else
		retval = MED_ALLOW;
	medusa_put_upper_and_parent(&ndupper, NULL);
	return retval;
}

device_initcall(symlink_acctype_init);

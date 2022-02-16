// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'rename' access type, with subj=task and obj=inode */

struct rename_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	char newname[NAME_MAX+1];
};

MED_ATTRS(rename_access) {
	MED_ATTR_RO(rename_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(rename_access, newname, "newname", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(rename_access, "rename", process_kobject, "process",
		file_kobject, "file");

int __init rename_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(rename_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_rename(struct dentry *old_dentry, const char *newname)
{
	struct rename_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;
	int newnamelen;

	dentry2string(old_dentry, access.filename);
	newnamelen = strlen(newname);
	if (newnamelen > NAME_MAX)
		newnamelen = NAME_MAX;
	memcpy(access.newname, newname, newnamelen);
	access.newname[newnamelen] = '\0';
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, old_dentry->d_inode);
	file_kobj_live_add(old_dentry->d_inode);
	retval = MED_DECIDE(rename_access, &access, &process, &file);
	file_kobj_live_remove(old_dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_rename(const struct path *old_path,
				struct dentry *old_dentry,
				const struct path *new_path,
				struct dentry *new_dentry)
{
	enum medusa_answer_t r;
	struct path target_upper;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(inode_security(old_dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry_dir(old_path->mnt, old_dentry) <= 0) {
		return MED_ALLOW;
	}
	/* check S and W access to old_dentry */
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(old_dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(old_dentry->d_inode)))
	)
		return MED_DENY;

	medusa_get_upper_and_parent(new_path, &target_upper, NULL);
	if (!is_med_magic_valid(&(inode_security(target_upper.dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry_dir(target_upper.mnt, target_upper.dentry) <= 0) {
		medusa_put_upper_and_parent(&target_upper, NULL);
		return MED_ALLOW;
	}
	/* check S and W access to target_upper */
	/* med_pr_info("target_upper=%pd4 new_dentry=%pd4\n", target_upper.dentry, new_dentry); */
	/* med_pr_info("Scur=%*pbl Wcur=%*pbl Starget_upper=%*pbl\n", CONFIG_MEDUSA_VS, &VSS(task_security(current)), CONFIG_MEDUSA_VS, &VSW(task_security(current)), CONFIG_MEDUSA_VS, &VS(inode_security(target_upper.dentry->d_inode))); */
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(target_upper.dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(target_upper.dentry->d_inode)))) {
		medusa_put_upper_and_parent(&target_upper, NULL);
		return MED_DENY;
	}

	r = MED_ALLOW;
	if (MEDUSA_MONITORED_ACCESS_O(rename_access, inode_security(old_dentry->d_inode)))
		r = medusa_do_rename(old_dentry, new_dentry->d_name.name);
	med_magic_invalidate(&(inode_security(old_dentry->d_inode)->med_object));
	return r;
}

device_initcall(rename_acctype_init);

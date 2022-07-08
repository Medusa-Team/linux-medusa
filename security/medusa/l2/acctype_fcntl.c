// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'fcntl' access type, with subj=task and obj=inode */

struct fcntl_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	unsigned int cmd;
	unsigned long arg;
};

MED_ATTRS(fcntl_access) {
	MED_ATTR_RO(fcntl_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(fcntl_access, cmd, "cmd", MED_UNSIGNED),
	MED_ATTR_RO(fcntl_access, arg, "arg", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(fcntl_access, "fcntl", process_kobject, "process",
	file_kobject, "file");

int __init fcntl_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(fcntl_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_fcntl(struct file *file, unsigned int cmd,
					unsigned long arg, struct inode *inode)
{
	struct fcntl_access access;
	struct process_kobject process;
	struct file_kobject kfile;
	enum medusa_answer_t retval;

	access.cmd = cmd;
	access.arg = arg;
	file_kobj_dentry2string_mnt(&file->f_path, file_dentry(file), access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&kfile, inode);
	file_kobj_live_add(inode);
	retval = MED_DECIDE(fcntl_access, &access, &process, &kfile);
	file_kobj_live_remove(inode);
	return retval;
}

enum medusa_answer_t medusa_fcntl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct inode *inode = file_inode(file);
	if (unlikely(IS_PRIVATE(inode))) {
		return MED_ALLOW;
	}

	if (cmd != F_SETLK && cmd != F_SETLKW &&
		cmd != F_SETOWN && cmd != F_SETSIG && cmd != F_SETFL) {
		return MED_ALLOW;
	}

	if (cmd == F_SETFL && !((arg ^ file->f_flags) & O_APPEND)) {
		return MED_ALLOW;
	}

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0) {
		return MED_ALLOW;
	}

	if (!is_med_magic_valid(&(inode_security(inode)->med_object)) &&
		file_kobj_validate_dentry_dir(file->f_path.mnt, file_dentry(file)) <= 0) {
		return MED_ALLOW;
	}
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(inode)))
	)
		return MED_DENY;
	med_pr_debug("file_fcntl: dev=%u ino=%lu vs=%*pbl act=%*pbl\n", inode->i_sb->s_dev, inode->i_ino, CONFIG_MEDUSA_VS, &VS(inode_security(inode)), CONFIG_MEDUSA_ACT, &inode_security(inode)->med_object.act);
	if (MEDUSA_MONITORED_ACCESS_O(fcntl_access, inode_security(inode))) {
		return medusa_do_fcntl(file, cmd, arg, inode);
	}
	return MED_ALLOW;
}

device_initcall(fcntl_acctype_init);

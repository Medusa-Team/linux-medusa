// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'mknod' access type, with subj=task and obj=inode */

struct mknod_access {
MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	dev_t dev;
	int mode;
};

MED_ATTRS(mknod_access) {
	MED_ATTR_RO(mknod_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(mknod_access, dev, "dev", MED_UNSIGNED),
	MED_ATTR_RO(mknod_access, mode, "mode", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(mknod_access, "mknod", process_kobject, "process",
			file_kobject, "file");

int __init mknod_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(mknod_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_mknod(struct dentry *parent, struct dentry *dentry, dev_t dev, int mode)
{
	struct mknod_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	memset(&access, '\0', sizeof(struct mknod_access));
	/* process_kobject process is zeroed by process_kern2kobj function */
	/* file_kobject file is zeroed by file_kern2kobj function */

	file_kobj_dentry2string(dentry, access.filename);
	access.dev = dev;
	access.mode = mode;
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, parent->d_inode);
	file_kobj_live_add(parent->d_inode);
	retval = MED_DECIDE(mknod_access, &access, &process, &file);
	file_kobj_live_remove(parent->d_inode);
	return retval;
}

enum medusa_answer_t medusa_mknod(struct dentry *dentry, dev_t dev, int mode)
{
	struct path ndcurrent, ndupper, ndparent;
	enum medusa_answer_t retval;

	if (!dentry || IS_ERR(dentry))
		return MED_ALLOW;
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	ndcurrent.dentry = dentry;
	ndcurrent.mnt = NULL;
	medusa_get_upper_and_parent(&ndcurrent, &ndupper, &ndparent);

	if (!is_med_magic_valid(&(inode_security(ndparent.dentry->d_inode)->med_object)) &&
			file_kobj_validate_dentry(ndparent.dentry,ndparent.mnt) <= 0) {
		medusa_put_upper_and_parent(&ndupper, &ndparent);
		return MED_ALLOW;
	}
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(ndparent.dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(ndparent.dentry->d_inode)))
	) {
		medusa_put_upper_and_parent(&ndupper, &ndparent);
		return MED_DENY;
	}
	if (MEDUSA_MONITORED_ACCESS_O(mknod_access, inode_security(ndparent.dentry->d_inode)))
		retval = medusa_do_mknod(ndparent.dentry, ndupper.dentry, dev, mode);
	else
		retval = MED_ALLOW;
	medusa_put_upper_and_parent(&ndupper, &ndparent);
	return retval;
}

device_initcall(mknod_acctype_init);

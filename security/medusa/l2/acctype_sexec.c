// SPDX-License-Identifier: GPL-2.0-only

#include <linux/binfmts.h>
#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'sexec' access type, with subj=task and obj=inode */

struct sexec_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	kernel_cap_t cap_effective;
	kernel_cap_t cap_inheritable;
	kernel_cap_t cap_permitted;
	kuid_t uid;
	kgid_t gid;
};

MED_ATTRS(sexec_access) {
	MED_ATTR_RO(sexec_access, cap_effective, "ecap", MED_BITMAP | MED_LE),
	MED_ATTR_RO(sexec_access, cap_inheritable, "icap", MED_BITMAP | MED_LE),
	MED_ATTR_RO(sexec_access, cap_permitted, "pcap", MED_BITMAP | MED_LE),
	MED_ATTR_RO(sexec_access, uid, "uid", MED_SIGNED),
	MED_ATTR_RO(sexec_access, gid, "gid", MED_SIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(sexec_access, "sexec", process_kobject, "process",
		file_kobject, "file");

int __init sexec_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(sexec_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

/**
 * medusa_sexec - L1-called code to create access of type 'sexec'.
 * @inode: input inode for sexec() call
 * @mask: mask of access rights to validate
 *
 */

#define DENTRY (bprm->file->f_path.dentry)

static enum medusa_answer_t medusa_do_sexec(struct linux_binprm *bprm)
{
	struct sexec_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	/* clear all bitmaps... */
	memset(&access, '\0', sizeof(struct sexec_access));

	file_kobj_dentry2string(DENTRY, access.filename);
	access.cap_effective = bprm->cred->cap_effective;
	access.cap_inheritable = bprm->cred->cap_inheritable;
	access.cap_permitted = bprm->cred->cap_permitted;
	access.uid = bprm->cred->euid;
	access.gid = bprm->cred->egid;
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, DENTRY->d_inode);
	file_kobj_live_add(DENTRY->d_inode);
	retval = MED_DECIDE(sexec_access, &access, &process, &file);
	file_kobj_live_remove(DENTRY->d_inode);
	return retval;
}

enum medusa_answer_t medusa_sexec(struct linux_binprm *bprm)
{
	enum medusa_answer_t retval = MED_ALLOW;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(inode_security(DENTRY->d_inode)->med_object)) &&
		file_kobj_validate_dentry(DENTRY, bprm->file->f_path.mnt, NULL) <= 0)
		return MED_ALLOW;
	/* no sense in checking VS here */
	if (MEDUSA_MONITORED_ACCESS_S(sexec_access, task_security(current)))
		retval = medusa_do_sexec(bprm);
	return retval;
}

#undef DENTRY

device_initcall(sexec_acctype_init);

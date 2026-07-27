// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'open' access type, with subj=task and obj=inode */

struct open_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX + 1];
};

MED_ATTRS(open_access) {
	MED_ATTR_RO(open_access, filename, "filename", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(open_access, "open",
	    process_kobject, "process",
	    file_kobject, "file");

static int __init open_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(open_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static struct medusa_decision_result
medusa_do_open(const struct path *path, struct inode *inode)
{
	struct open_access access;
	struct process_kobject process;
	struct file_kobject file;
	struct medusa_decision_result result;

	file_kobj_dentry2string_mnt(path, path->dentry, access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, inode);
	file_kobj_live_add(inode);
	result = MED_DECIDE_RESULT(open_access, &access, &process, &file);
	file_kobj_live_remove(inode);
	return result;
}

enum medusa_answer_t medusa_open(struct file *file)
{
	struct common_audit_data cad;
	struct medusa_audit_data mad = { MEDUSA_AUDIT_DATA_INIT };

	const struct path *path = &file->f_path;
	const u8 acc_mode = ACC_MODE(file->f_flags);
	unsigned int requested = MEDUSA_VS_SEE;
	// TODO: Can we use file_inode?
	struct inode *inode = d_backing_inode(path->dentry);

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0)
		return mad.ans;

	if (!is_med_magic_valid(&(inode_security(inode)->med_object)) &&
	    file_kobj_validate_dentry_dir(path->mnt, path->dentry) <= 0)
		return mad.ans;

	if (acc_mode & MAY_READ)
		requested |= MEDUSA_VS_READ;
	if (acc_mode & MAY_WRITE)
		requested |= MEDUSA_VS_WRITE;

	if (!medusa_vs_access_allowed(&task_security(current)->med_subject,
				      &inode_security(inode)->med_object,
				      requested)) {
		mad.vs.sw.vst = VS(inode_security(inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		medusa_audit_apply_local(&mad, MED_DENY,
					 MEDUSA_DECISION_VIRTUAL_SPACE);
		goto audit;
	}
	if (MEDUSA_MONITORED_ACCESS_O(open_access, inode_security(inode))) {
		medusa_audit_apply_decision(&mad,
					    medusa_do_open(path, inode));
	}

audit:
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_NONE;
		cad.u.tsk = current;
		mad.function = "open";
		mad.path.path = &file->f_path;
		mad.path.mode = acc_mode;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_path_mode_cb);
	}
	return mad.ans;
}

device_initcall(open_acctype_init);

// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'chmod' access type, with subj=task and obj=inode */

struct chmod_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX + 1];
	umode_t mode;
};

MED_ATTRS(chmod_access) {
	MED_ATTR_RO(chmod_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(chmod_access, mode, "mode", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(chmod_access, "chmod",
	    process_kobject, "process",
	    file_kobject, "file");

static int __init chmod_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(chmod_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_chmod_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_d_path(ab, " dir=", mad->path.path);
	audit_log_format(ab, " mode=%d", mad->path.mode);
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static struct medusa_decision_result
medusa_do_chmod(const struct path *path, umode_t mode)
{
	struct chmod_access access;
	struct process_kobject process;
	struct file_kobject file;
	struct medusa_decision_result result;

	access.mode = mode;
	file_kobj_dentry2string_mnt(path, path->dentry, access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, path->dentry->d_inode);
	file_kobj_live_add(path->dentry->d_inode);
	result = MED_DECIDE_RESULT(chmod_access, &access, &process, &file);
	file_kobj_live_remove(path->dentry->d_inode);
	return result;
}

enum medusa_answer_t medusa_chmod(const struct path *path, umode_t mode)
{
	struct common_audit_data cad;
	struct medusa_audit_data mad = { MEDUSA_AUDIT_DATA_INIT };

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(chmod_access))
		return mad.ans;

	if (!is_med_magic_valid(&(inode_security(path->dentry->d_inode)->med_object)) &&
	    file_kobj_validate_dentry_dir(path->mnt, path->dentry) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(chmod_access))
		return mad.ans;
	if (!vs_intersects(VSS(task_security(current)),
			   VS(inode_security(path->dentry->d_inode))) ||
	    !vs_intersects(VSW(task_security(current)),
			   VS(inode_security(path->dentry->d_inode)))) {
		mad.vs.sw.vst = VS(inode_security(path->dentry->d_inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		medusa_audit_apply_local(&mad, MED_DENY,
					 MEDUSA_DECISION_VIRTUAL_SPACE);
		goto audit;
	}
	if (MEDUSA_MONITORED_ACCESS_O(chmod_access, inode_security(path->dentry->d_inode))) {
		medusa_audit_apply_decision(&mad,
					    medusa_do_chmod(path, mode));
	}
audit:
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_NONE;
		cad.u.tsk = current;
		mad.function = "chmod";
		mad.path.path = path;
		mad.path.mode = mode;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_chmod_pacb);
	}
	return mad.ans;
}

device_initcall(chmod_acctype_init);

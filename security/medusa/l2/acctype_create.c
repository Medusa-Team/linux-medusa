// SPDX-License-Identifier: GPL-2.0

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'create' access type, with subj=task and obj=inode */

struct create_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX + 1];
	int mode;
};

MED_ATTRS(create_access) {
	MED_ATTR_RO(create_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(create_access, mode, "mode", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(create_access, "create",
	    process_kobject, "process",
	    file_kobject, "file");

static int __init create_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(create_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static struct medusa_decision_result
medusa_do_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct create_access access;
	struct process_kobject process;
	struct file_kobject file;
	struct medusa_decision_result result;

	dentry2string(dentry, access.filename);
	access.mode = mode;
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, dir);
	file_kobj_live_add(dir);
	result = MED_DECIDE_RESULT(create_access, &access, &process, &file);
	file_kobj_live_remove(dir);
	return result;
}

static void medusa_create_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_format(ab, " mode=%d", mad->path.mode);
}

enum medusa_answer_t medusa_create(struct inode *dir, struct dentry *dentry,
				   umode_t mode)
{
	struct common_audit_data cad;
	struct medusa_audit_data mad = { MEDUSA_AUDIT_DATA_INIT };
	struct medusa_decision_result cached;
	u64 subject_domain;
	bool validation_failed = false;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(create_access)) {
		medusa_audit_apply_local(&mad, MED_ALLOW,
					 MEDUSA_DECISION_VALIDATION);
		validation_failed = true;
		goto audit;
	}

	subject_domain =
		atomic64_read(&task_security(current)->policy_domain);
	if (MEDUSA_MONITORED_ACCESS_O(create_access, inode_security(dir)) &&
	    medusa_domain_cache_decide(&MED_EVTYPEOF(create_access),
				       subject_domain, 0, (u64)mode,
				       &cached)) {
		medusa_audit_apply_decision(&mad, cached);
		goto audit;
	}

	/*
	 * inode_create provides no vfsmount, so the path-based getfile
	 * validator cannot safely reconstruct a parent path here.
	 */
	if (!is_med_magic_valid(&(inode_security(dir)->med_object)) &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(create_access)) {
		medusa_audit_apply_local(&mad, MED_ALLOW,
					 MEDUSA_DECISION_VALIDATION);
		validation_failed = true;
		goto audit;
	}
	if (!vs_intersects(VSS(task_security(current)),
			   VS(inode_security(dir))) ||
	    !vs_intersects(VSW(task_security(current)),
			   VS(inode_security(dir)))) {
		mad.vs.sw.vst = VS(inode_security(dir));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		medusa_audit_apply_local(&mad, MED_DENY,
					 MEDUSA_DECISION_VIRTUAL_SPACE);
		goto audit;
	}
	if (MEDUSA_MONITORED_ACCESS_O(create_access, inode_security(dir))) {
		medusa_audit_apply_decision(&mad,
					    medusa_do_create(dir, dentry, mode));
	}
audit:
	if (task_security(current)->audit || validation_failed ||
	    mad.unavailable != MEDUSA_AVAILABLE) {
		cad.type = LSM_AUDIT_DATA_DENTRY;
		cad.u.dentry = dentry;
		mad.function = "create";
		mad.path.mode = mode;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_create_pacb);
	}
	return mad.ans;
}

device_initcall(create_acctype_init);

// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'permission' access type, with subj=task and obj=inode */

struct permission_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX + 1];
	int mask;
};

MED_ATTRS(permission_access) {
	MED_ATTR_RO(permission_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(permission_access, mask, "mask", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(permission_access, "permission",
	    process_kobject, "process",
	    file_kobject, "file");

static int __init permission_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(permission_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_permission_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_format(ab, " mask=%d", mad->mask);
}

static struct medusa_decision_result
medusa_do_permission(struct dentry *dentry, struct inode *inode, int mask)
{
	struct permission_access access;
	struct process_kobject process;
	struct file_kobject file;
	struct medusa_decision_result result;

	file_kobj_dentry2string(dentry, access.filename);
	access.mask = mask;
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, inode);
	file_kobj_live_add(inode);
	result = MED_DECIDE_RESULT(permission_access, &access, &process, &file);
	file_kobj_live_remove(inode);
	return result;
}

/**
 * medusa_permission - L1-called code to create access of type 'permission'.
 * @inode: input inode for permission() call
 * @mask: mask of access rights to validate
 *
 */
enum medusa_answer_t medusa_permission(struct inode *inode, int mask)
{
	struct common_audit_data cad;
	struct medusa_audit_data mad = { MEDUSA_AUDIT_DATA_INIT };
	struct dentry *dentry;
	unsigned int requested = MEDUSA_VS_SEE;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(permission_access))
		return mad.ans;

	dentry = d_find_alias(inode);

	if (!dentry || IS_ERR(dentry))
		return mad.ans;
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(permission_access))
		return mad.ans;
	if (!is_med_magic_valid(&(inode_security(inode)->med_object)) &&
	    file_kobj_validate_dentry(dentry, NULL, NULL) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(permission_access))
		goto out_dput;
	if (mask & (S_IRUGO | S_IXUGO))
		requested |= MEDUSA_VS_READ;
	if (mask & S_IWUGO)
		requested |= MEDUSA_VS_WRITE;

	if (!medusa_vs_access_allowed(&task_security(current)->med_subject,
				      &inode_security(inode)->med_object,
				      requested)) {
		mad.vs.srw.vst = VS(inode_security(inode));
		mad.vs.srw.vss = VSS(task_security(current));
		mad.vs.srw.vsr = VSR(task_security(current));
		mad.vs.srw.vsw = VSW(task_security(current));
		medusa_audit_apply_local(&mad, MED_DENY,
					 MEDUSA_DECISION_VIRTUAL_SPACE);
		goto out_dput;
	}
	if (MEDUSA_MONITORED_ACCESS_O(permission_access, inode_security(inode))) {
		medusa_audit_apply_decision(&mad,
					    medusa_do_permission(dentry, inode,
								 mask));
	}
out_dput:
	cad.type = LSM_AUDIT_DATA_DENTRY;
	cad.u.dentry = dentry;
	mad.function = "permission";
	mad.mask = mask;
	cad.medusa_audit_data = &mad;
	medusa_audit_log_callback(&cad, medusa_permission_pacb);
	dput(dentry);
	return mad.ans;
}

device_initcall(permission_acctype_init);

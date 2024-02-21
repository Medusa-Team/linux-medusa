// SPDX-License-Identifier: GPL-2.0-only

/* (C) 2002 Milan Pikula
 *
 * This file defines the 'setresuid' access type, with object=subject=process.
 */
#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/audit_medusa.h"

struct setresuid {
	MEDUSA_ACCESS_HEADER;
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	int flags;
};

MED_ATTRS(setresuid) {
	MED_ATTR_RO(setresuid, ruid, "ruid", MED_SIGNED),
	MED_ATTR_RO(setresuid, euid, "euid", MED_SIGNED),
	MED_ATTR_RO(setresuid, suid, "suid", MED_SIGNED),
	MED_ATTR_RO(setresuid, flags, "flags", MED_SIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(setresuid, "setresuid", process_kobject, "process", process_kobject, "process");

static int __init setresuid_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(setresuid, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

static void medusa_setresuid_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_format(ab, " old_ruid=%d", mad->setresuid.old_ruid);
	audit_log_format(ab, " old_euid=%d", mad->setresuid.old_euid);
	audit_log_format(ab, " old_suid=%d", mad->setresuid.old_suid);
	audit_log_format(ab, " ruid=%d", mad->setresuid.ruid);
	audit_log_format(ab, " euid=%d", mad->setresuid.euid);
	audit_log_format(ab, " suid=%d", mad->setresuid.suid);
}

static inline char *setid_op_name(int flags)
{
	switch (flags) {
	case LSM_SETID_RE:
		return "setreuid";
	case LSM_SETID_ID:
		return "setuid";
	case LSM_SETID_RES:
		return "setresuid";
	case LSM_SETID_FS:
		return "setfsuid";
	default:
		WARN_ONCE(1, "Unexpected flag from security_task_fix_setuid.\n");
		return "setid_unknown";
	}
}

enum medusa_answer_t medusa_setresuid(struct cred *new,
				      const struct cred *old,
				      int flags)
{
	struct setresuid access;
	struct process_kobject process;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .ans = MED_ALLOW, .as = AS_NO_REQUEST };
	uid_t ruid = new->uid.val;
	uid_t euid = new->euid.val;
	uid_t suid = new->suid.val;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (MEDUSA_MONITORED_ACCESS_S(setresuid, task_security(current))) {
		access.ruid = ruid;
		access.euid = euid;
		access.suid = suid;
		access.flags = flags;
		process_kern2kobj(&process, current);
		mad.ans = MED_DECIDE(setresuid, &access, &process, &process);
		mad.as = AS_REQUEST;
	}

	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_NONE;
		cad.u.tsk = current;
		mad.function = setid_op_name(flags);
		mad.setresuid.ruid = ruid;
		mad.setresuid.euid = euid;
		mad.setresuid.suid = suid;
		mad.setresuid.old_ruid = old->uid.val;
		mad.setresuid.old_euid = old->euid.val;
		mad.setresuid.old_suid = old->suid.val;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_setresuid_pacb);
	}

	return mad.ans;
}

device_initcall(setresuid_acctype_init);

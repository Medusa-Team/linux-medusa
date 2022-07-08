// SPDX-License-Identifier: GPL-2.0-only

/* (C) 2002 Milan Pikula
 *
 * This file defines the 'setresuid' access type, with object=subject=process.
 */
#include "l3/registry.h"
#include "l2/kobject_process.h"

struct setresuid {
	MEDUSA_ACCESS_HEADER;
	uid_t ruid;
	uid_t euid;
	uid_t suid;
};

MED_ATTRS(setresuid) {
	MED_ATTR_RO(setresuid, ruid, "ruid", MED_SIGNED),
	MED_ATTR_RO(setresuid, euid, "euid", MED_SIGNED),
	MED_ATTR_RO(setresuid, suid, "suid", MED_SIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(setresuid, "setresuid", process_kobject, "process", process_kobject, "process");

int __init setresuid_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(setresuid, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

enum medusa_answer_t medusa_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	struct setresuid access;
	struct process_kobject process;
	enum medusa_answer_t retval = MED_ALLOW;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (MEDUSA_MONITORED_ACCESS_S(setresuid, task_security(current))) {
		access.ruid = ruid;
		access.euid = euid;
		access.suid = suid;
		process_kern2kobj(&process, current);
		retval = MED_DECIDE(setresuid, &access, &process, &process);
	}

	return retval;
}

device_initcall(setresuid_acctype_init);

// SPDX-License-Identifier: GPL-2.0

/* (C) 2002 Milan Pikula
 *
 * This file defines the 'medusa_capable' call.
 */

#include "l3/registry.h"
#include "l2/kobject_process.h"

struct capable_access {
	MEDUSA_ACCESS_HEADER;
	__u32 cap;
};

MED_ATTRS(capable_access) {
	MED_ATTR_RO(capable_access, cap, "cap", MED_BITMAP | MED_LE),
	MED_ATTR_END
};

MED_ACCTYPE(capable_access, "capable",
		process_kobject, "process",
		process_kobject, "process");

int __init capable_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(capable_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

enum medusa_answer_t medusa_capable(int cap)
{
	struct capable_access access;
	struct process_kobject process;
	enum medusa_answer_t retval;

	if (!in_task()) {
		med_pr_warn("CAPABLE IN INTERRUPT\n");
#warning "finish me"
		return MED_ALLOW;
	}

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (MEDUSA_MONITORED_ACCESS_S(capable_access, task_security(current))) {
		access.cap = CAP_TO_MASK(cap);
		process_kern2kobj(&process, current);
		retval = MED_DECIDE(capable_access, &access, &process, &process);
		return retval;
	}

	return MED_ALLOW;
}

device_initcall(capable_acctype_init);

// SPDX-License-Identifier: GPL-2.0

#include "l3/registry.h"
#include "l2/kobject_process.h"

/* let's define the 'fork' access type, with object=task and subject=task. */

struct fork_access {
	MEDUSA_ACCESS_HEADER;
	unsigned long clone_flags;
};

MED_ATTRS(fork_access) {
	MED_ATTR_RO(fork_access, clone_flags, "clone_flags", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(fork_access, "fork", process_kobject, "parent", process_kobject, "parent");

int __init fork_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(fork_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

enum medusa_answer_t medusa_fork(unsigned long clone_flags)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct fork_access access;
	struct process_kobject parent;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (MEDUSA_MONITORED_ACCESS_S(fork_access, task_security(current))) {
		access.clone_flags = clone_flags;
		process_kern2kobj(&parent, current);
		retval = MED_DECIDE(fork_access, &access, &parent, &parent);
	}
	return retval;
}

device_initcall(fork_acctype_init);

// SPDX-License-Identifier: GPL-2.0

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

struct init_process {
	MEDUSA_ACCESS_HEADER;
};

MED_ATTRS(init_process) {
	MED_ATTR_END
};

MED_ACCTYPE(init_process, "init", process_kobject, "process", process_kobject, "parent");

int __init init_process_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(init_process, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

enum medusa_answer_t medusa_init_process(struct task_struct *new)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct init_process access;
	struct process_kobject process;
	struct process_kobject parent;

	if (!is_med_magic_valid(&(task_security(new)->med_object)) &&
		process_kobj_validate_task(new) <= 0)
		return MED_ALLOW;

	/* inherit from parent if the action isn't monitored? */
	if (MEDUSA_MONITORED_ACCESS_S(init_process, task_security(new))) {
		process_kern2kobj(&process, new);
		process_kern2kobj(&parent, current);
		retval = MED_DECIDE(init_process, &access, &process, &parent);
	}
	return retval;
}

void medusa_kernel_thread(int (*fn) (void *))
{
	init_med_object(&(task_security(current)->med_object));
	init_med_subject(&(task_security(current)->med_subject));
	task_security(current)->luid = INVALID_UID;
}

device_initcall(init_process_acctype_init);

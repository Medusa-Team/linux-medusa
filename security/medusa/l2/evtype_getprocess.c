/* (C) 2002 Milan Pikula */

#include <linux/medusa/l3/registry.h>
#include <linux/init.h>
#include <linux/mm.h>

#include "kobject_process.h"
#include <linux/medusa/l1/process_handlers.h>

/*
 *
 * This routine has to validate the process. Because we don't have
 * the (useful) information to build the process hierarchy, it is
 * useless to call L3 here. We do it anyway: otherwise the first
 * access after restart of auth. server will go with full VS set,
 * and thus will succeed.
 *
 */

struct getprocess_event {
	MEDUSA_ACCESS_HEADER;
};

MED_ATTRS(getprocess_event) {
	MED_ATTR_END
};
MED_EVTYPE(getprocess_event, "getprocess", process_kobject, "process",
		process_kobject, "process");

/*
 * This routine expects the existing, but !MED_MAGIC_VALID Medusa task_struct security struct!
 */
int process_kobj_validate_task(struct task_struct * ts)
{
	medusa_answer_t retval;
	struct getprocess_event event;
	struct process_kobject proc;

        memset(&event, '\0', sizeof(struct getprocess_event));
        /* process_kobject proc is zeroed by process_kern2kobj function */

	init_med_object(&(&task_security(ts))->med_object);
	init_med_subject(&(&task_security(ts))->med_subject);
#ifdef CONFIG_MEDUSA_FORCE
	task_security(ts).force_code = NULL;
#endif
	process_kern2kobj(&proc, ts);
	retval = MED_DECIDE(getprocess_event, &event, &proc, &proc);
	if (retval != MED_ERR)
		return 1;
	return -1;
}

int __init getprocess_evtype_init(void) {
	MED_REGISTER_EVTYPE(getprocess_event,
			MEDUSA_EVTYPE_NOTTRIGGERED);
	return 0;
}
__initcall(getprocess_evtype_init);

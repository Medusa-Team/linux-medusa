// SPDX-License-Identifier: GPL-2.0

/* (C) 2002 Milan Pikula */

#include "l3/registry.h"
#include "l2/kobject_process.h"

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
		process_kobject, "parent");

/*
 * This routine expects the existing, but !is_med_magic_valid Medusa task_struct security struct!
 */
int process_kobj_validate_task(struct task_struct *ts)
{
	enum medusa_answer_t retval;
	struct getprocess_event event;
	struct process_kobject proc;
	struct process_kobject parent;
	struct task_struct *ts_parent;
	int err;

	/* nothing to do if there is no running authserver */
	if (!med_is_authserver_present())
		return 0;

	init_med_object(&(task_security(ts)->med_object));
	init_med_subject(&(task_security(ts)->med_subject));
#ifdef CONFIG_MEDUSA_FORCE
	task_security(ts)->force_code = NULL;
#endif

	/*
	 * Get the parent's task:
	 * 1) in the case of multi-threaded program get the leader,
	 * 2) parent otherwise.
	 */
	rcu_read_lock();
	if (!thread_group_leader(ts))
		ts_parent = rcu_dereference(ts->group_leader);
	else
		ts_parent = rcu_dereference(ts->real_parent);
	if (unlikely(!ts_parent)) {
		rcu_read_unlock();
		return -1;
	}
	get_task_struct(ts_parent);
	rcu_read_unlock();

	/* recursive call parent's validation if necessary */
	if (ts == ts_parent)
		goto init_always_do_direct_getprocess;

	mutex_lock_nested(&(task_security(ts_parent)->validation_in_progress),
			  task_security(current)->validation_depth_nesting);
	task_security(current)->validation_depth_nesting++;
	if (!is_med_magic_valid(&(task_security(ts_parent)->med_object)) &&
		(err = process_kobj_validate_task(ts_parent)) <= 0) {
		put_task_struct(ts_parent);
		mutex_unlock(&(task_security(ts_parent)->validation_in_progress));
		task_security(current)->validation_depth_nesting--;
		return err;
	}
	task_security(current)->validation_depth_nesting--;
	mutex_unlock(&(task_security(ts_parent)->validation_in_progress));

	/*
	 * If triggering of the getprocess event in the parent's security
	 * information field is turned off, take the VS model for a new
	 * Medusa's process object from its parent task.
	 *
	 * Attention: Credentials (capabilities, IDs, GIDs) are not inherited!
	 */
	if (!MEDUSA_MONITORED_ACCESS_S(getprocess_event,
				       task_security(ts_parent))) {
		task_security(ts)->med_subject = task_security(ts_parent)->med_subject;
		task_security(ts)->med_object = task_security(ts_parent)->med_object;
		task_security(ts)->audit = task_security(ts_parent)->audit;
#if (defined(CONFIG_X86) || defined(CONFIG_X86_64)) && defined(CONFIG_MEDUSA_SYSCALL)
		memcpy(task_security(ts)->med_syscall,
		       task_security(ts_parent)->med_syscall,
		       sizeof(task_security(ts)->med_syscall));
#endif
		put_task_struct(ts_parent);
		return 1;
	}

init_always_do_direct_getprocess:
	process_kern2kobj(&parent, ts_parent);
	put_task_struct(ts_parent);

	get_cmdline(ts, task_security(ts)->cmdline, sizeof(task_security(ts)->cmdline));
	process_kern2kobj(&proc, ts);
	retval = MED_DECIDE(getprocess_event, &event, &proc, &parent);
	if (retval != MED_ERR)
		return is_med_magic_valid(&(task_security(ts)->med_object));
	return -1;
}

int __init getprocess_evtype_init(void)
{
	/*
	 * Triggering of this event can be turned off to permit VS model
	 * inheriting: if parent of newly created Medusa's task object does not
	 * trigger getprocess event, the new task inherites parent's VS model.
	 *
	 * Attention: Credentials (capabilities, IDs, GIDs) are not inherited!
	 */
	MED_REGISTER_EVTYPE(getprocess_event,
			MEDUSA_EVTYPE_TRIGGEREDATSUBJECT |
			MEDUSA_EVTYPE_TRIGGEREDBYSUBJECTBIT);
	return 0;
}
device_initcall(getprocess_evtype_init);

// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l3/arch.h"
#include "l2/kobject_process.h"
#include "l2/audit_medusa.h"

/* let's define the 'ptrace' access type, with object=task and subject=task. */

struct ptrace_access {
	MEDUSA_ACCESS_HEADER;
	unsigned int mode;
	unsigned int operation;
};

MED_ATTRS(ptrace_access) {
	MED_ATTR_RO(ptrace_access, mode, "mode", MED_UNSIGNED),
	MED_ATTR_RO(ptrace_access, operation, "operation", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(ptrace_access, "ptrace",
	    process_kobject, "tracer",
	    process_kobject, "tracee");

static int __init ptrace_acctype_init(void)
{
	/* to object or not to object? now THAT is a question ;). */
	MED_REGISTER_ACCTYPE(ptrace_access,
			     MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

enum medusa_answer_t medusa_ptrace(struct task_struct *tracer,
				   struct task_struct *tracee,
				   unsigned int mode,
				   enum medusa_ptrace_operation operation)
{
	struct ptrace_access access;
	struct process_kobject tracer_p;
	struct process_kobject tracee_p;
	bool can_validate = in_task() && !preempt_count() && !irqs_disabled();
	bool tracer_valid;
	bool tracee_valid;

	tracer_valid =
		is_med_magic_valid(&(task_security(tracer)->med_object));
	tracee_valid =
		is_med_magic_valid(&(task_security(tracee)->med_object));

	if (can_validate && !tracer_valid)
		tracer_valid = process_kobj_validate_task(tracer) > 0;
	if (can_validate && !tracee_valid)
		tracee_valid = process_kobj_validate_task(tracee) > 0;

	if (tracer_valid && tracee_valid &&
	    (!vs_intersects(VSS(task_security(tracer)),
			    VS(task_security(tracee))) ||
	     !vs_intersects(VSW(task_security(tracer)),
			    VS(task_security(tracee)))))
		return MED_DENY;

	if (MEDUSA_MONITORED_ACCESS_S(ptrace_access, task_security(tracer)) ||
	    !tracer_valid || !tracee_valid) {
		access.mode = mode;
		access.operation = operation;
		process_kern2kobj(&tracer_p, tracer);
		process_kern2kobj(&tracee_p, tracee);
		return medusa_audit_decision_result("ptrace",
			MED_DECIDE_RESULT(ptrace_access, &access,
					  &tracer_p, &tracee_p),
			task_security(tracer)->audit);
	}

	return medusa_audit_cached_allow("ptrace",
					 task_security(tracer)->audit);
}

device_initcall(ptrace_acctype_init);

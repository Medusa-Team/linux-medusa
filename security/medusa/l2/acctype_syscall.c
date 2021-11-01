// SPDX-License-Identifier: GPL-2.0-only

#include <linux/linkage.h>
#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l3/med_model.h>
#include "kobject_process.h"
#include <linux/medusa/l1/task.h>
#include <linux/init.h>
#include <linux/mm.h>

/* let's define the 'syscall' access type, with subject=task and object=task. */

struct syscall_access {
	MEDUSA_ACCESS_HEADER;
	unsigned int sysnr;
	unsigned int arg1;
	unsigned int arg2;
	unsigned int arg3;
	unsigned int arg4;
	unsigned int arg5;
	unsigned int arg6;
	unsigned int arg7;
	/* is that enough on all archs? */
};

MED_ATTRS(syscall_access) {
	MED_ATTR_RO(syscall_access, sysnr, "sysnr", MED_UNSIGNED),
	MED_ATTR(syscall_access, arg1, "arg1", MED_UNSIGNED),
	MED_ATTR(syscall_access, arg2, "arg2", MED_UNSIGNED),
	MED_ATTR(syscall_access, arg3, "arg3", MED_UNSIGNED),
	MED_ATTR(syscall_access, arg4, "arg4", MED_UNSIGNED),
	MED_ATTR(syscall_access, arg5, "arg5", MED_UNSIGNED),
	MED_ATTR(syscall_access, arg6, "arg6", MED_UNSIGNED),
	MED_ATTR(syscall_access, arg7, "arg7", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(syscall_access, "syscall", process_kobject, "process", process_kobject, "process");

int __init syscall_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(syscall_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

asmlinkage enum medusa_answer_t medusa_syscall_i386(
	unsigned int eax,  /* in: syscall #, out: retval */
	struct task_struct *curr,
	unsigned int p1,
	unsigned int p2,
	unsigned int p3,
	unsigned int p4,
	unsigned int p5)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct syscall_access access;
	struct process_kobject proc;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (MEDUSA_MONITORED_ACCESS_S(syscall_access, task_security(current))) {
		access.sysnr = eax;
		access.arg1 = p1; access.arg2 = p2;
		access.arg3 = p3; access.arg4 = p4;
		access.arg5 = p5;
		access.arg6 = access.arg7 = 0;
		process_kern2kobj(&proc, current);
		retval = MED_DECIDE(syscall_access, &access, &proc, &proc);
	}
	/* this needs more optimization some day */
	if (retval == MED_DENY)
		return 0; /* deny */
	if (retval != MED_FAKE_ALLOW)
		return 1; /* allow */
	return 2; /* skip trace code */
}

device_initcall(syscall_acctype_init);

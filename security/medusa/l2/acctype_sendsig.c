// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"

/* let's define the 'kill' access type, with object=task and subject=task. */

struct send_signal {
	MEDUSA_ACCESS_HEADER;
	int signal_number;
};

MED_ATTRS(send_signal) {
	MED_ATTR_RO(send_signal, signal_number, "signal_number", MED_SIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(send_signal, "kill", process_kobject, "sender", process_kobject, "receiver");

int __init sendsig_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(send_signal, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}
/* TODO: add the same type, triggered at OBJECT */

enum medusa_answer_t medusa_sendsig(int sig, struct kernel_siginfo *info, struct task_struct *p)
{
	enum medusa_answer_t retval;
	struct send_signal access;
	struct process_kobject sender;
	struct process_kobject receiver;

	if (!sig)
		return 0; /* null signal; existence test */

	if (!in_task())
		return MED_ALLOW;
	/* always allow signals coming from kernel - see kernel/signal.c:send_signalnal() */
	if (info == SEND_SIG_PRIV)
		return MED_ALLOW;
	/*
	 * if (info) switch (info->si_code) {
	 *	case CLD_TRAPPED:
	 *	case CLD_STOPPED:
	 *	case CLD_DUMPED:
	 *	case CLD_KILLED:
	 *	case CLD_EXITED:
	 *	case SI_KERNEL:
	 *		return MED_ALLOW;
	 * }
	 */
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(task_security(p)->med_object)) &&
		process_kobj_validate_task(p) <= 0)
		return MED_ALLOW;

	if (!vs_intersects(VSS(task_security(current)), VS(task_security(p))) ||
			!vs_intersects(VSW(task_security(current)), VS(task_security(p))))
		return MED_DENY;

	if (MEDUSA_MONITORED_ACCESS_S(send_signal, task_security(current))) {
		access.signal_number = sig;
		process_kern2kobj(&sender, current);
		process_kern2kobj(&receiver, p);
		retval = MED_DECIDE(send_signal, &access, &sender, &receiver);
		return retval;
	}
	return MED_ALLOW;
}

device_initcall(sendsig_acctype_init);

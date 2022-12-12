// SPDX-License-Identifier: GPL-2.0-only

#include "l2/kobject_process.h"

bool refcount_inc_if_zero(refcount_t *r)
{
	int val = 0;

	return atomic_try_cmpxchg_release(&r->refs, &val, 1);
}

static void delayed_put_task_struct(struct rcu_head *rhp)
{
	struct medusa_l1_task_s *medusa_task = container_of(rhp, struct medusa_l1_task_s, rcu);

	if (!refcount_dec_if_one(&medusa_task->rcu_cb_set))
		WARN_ONCE(1, "medusa: rcu_cb_set undefined value\n");

	WARN_ONCE(!medusa_task->self, "medusa: medusa_task->self NULL\n");
	put_task_struct(medusa_task->self);
}

enum medusa_answer_t medusa_sendsig(struct task_struct *p, struct kernel_siginfo *info,
				    int sig, const struct cred *cred)
{
	enum medusa_answer_t retval = MED_ALLOW;

	/* allow signalling from NMI, hard IRQ and soft IRQ */
	if (!in_task())
		return MED_ALLOW;

	/* always allow signals coming from the kernel */
	if ((info == SEND_SIG_PRIV) || (info && SI_FROMKERNEL(info)))
		return MED_ALLOW;

	/* USB IO: TODO list:
	 * 1) use security blob in the cred struct
	 * 2) move security context from task struct into cred struct
	 */
	if (cred)
		return MED_ALLOW;

	/* If tasklist_lock is not held, this code path is not in atomic context;
	 * may schedule (after RCU read-side unlocking). But first check if it's
	 * necessary: do it only if subject/object does not yet have assigned a
	 * security context.
	 */
	if (IS_ENABLED(CONFIG_SECURITY_MEDUSA_KILL_RESCHEDULING) &&
	    !lockdep_is_held(&tasklist_lock) &&
	    (!is_med_magic_valid(&(task_security(current)->med_object)) ||
	     !is_med_magic_valid(&(task_security(p)->med_object)))) {
		int rcu_depth = rcu_preempt_depth();

		get_task_struct(p);
		for (int i = 0; i < rcu_depth; i++)
			rcu_read_unlock();

		/* free of RCU and tasklist_lock; may schedule */

		retval = MED_ALLOW;

		if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
			process_kobj_validate_task(current) <= 0)
			retval = MED_ERR;

		if (!is_med_magic_valid(&(task_security(p)->med_object)) &&
			process_kobj_validate_task(p) <= 0)
			retval = MED_ERR;

		for (int i = 0; i < rcu_depth; i++)
			rcu_read_lock();

		/* After re-entering into RCU read-side:
		 * 1) If the task state is not TASK_DEAD, use put_task_struct().
		 *    In the case of a race with a dying task it's OK to call
		 *    put_task_struct(), because task_struct will be freed
		 *    *after* the current RCU GP thanks to the
		 *    task_struct:rcu_users mechanism.
		 * 2) If the task is dying, try to install RCU CB. If it's
		 *    already installed, within the current RCU GP can be
		 *    invoked put_task_struct() and the ref counter of the
		 *    task_struct will not reach zero.
		 * 3) If the task is dying and the RCU CB is not installed yet,
		 *    install it. With respect to the RCU CB API it should be
		 *    guaranteed that CB will be installed only once within a
		 *    given RCU GP. For that purpose we use rcu_cb_set flag.
		 *    Installing and executing of the CB races with the
		 *    task_struct:rcu_users mechanism [delayed_put_task_struct()
		 *    in kernel/exit.c], but it's OK. Either the kernel/exit.c
		 *    delayed_put_task_struct() or our delayed_put_task_struct()
		 *    CB can be the last to call final put_task_struct() after
		 *    the current RCU GP.
		 */
		if ((READ_ONCE(p->__state) == TASK_DEAD)
		    && refcount_inc_if_zero(&(task_security(p)->rcu_cb_set))) {
			task_security(p)->self = p;
			call_rcu(&task_security(p)->rcu, delayed_put_task_struct);
		} else
			put_task_struct(p);
	}

	/* If there was an unsuccessfull attempt to validate subject/object,
	 * take a default action: allow the operation.
	 */
	if (retval == MED_ERR)
		return MED_ALLOW;

	/* existence test */
	if (!sig) {
		/* check ability of the sender see existence of the receiver */
		if (!vs_intersects(VSS(task_security(current)), VS(task_security(p))))
			return MED_DENY;

		/* Our existence test doesn't check the permissions inevitable
		 * for success of intended data flow between the receiver and
		 * the sender (i.e. delivery of the signal).
		 */
		return MED_ALLOW;
	}

	/* check ability of the sender send an information to the receiver */
	if (!vs_intersects(VSW(task_security(current)), VS(task_security(p))))
		return MED_DENY;

	/* check ability of the receiver obtain an information from the sender */
	if (!vs_intersects(VSR(task_security(p)), VS(task_security(current))))
		return MED_DENY;

	return MED_ALLOW;
}

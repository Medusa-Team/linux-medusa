#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l2/audit_medusa.h>
#include <linux/medusa/l1/task.h>
#include <linux/medusa/l1/ipc.h>
#include <linux/lsm_audit.h>
#include <linux/init.h>
#include <linux/mm.h>
#include "kobject_process.h"
#include "kobject_ipc.h"

struct ipc_perm_access {
	MEDUSA_ACCESS_HEADER;
	unsigned int ipc_class;
	u32 perms;	/* desired (requested) permission set */
};

MED_ATTRS(ipc_perm_access) {
	MED_ATTR_RO (ipc_perm_access, perms, "perms", MED_UNSIGNED),
	MED_ATTR_RO (ipc_perm_access, ipc_class, "ipc_class", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(ipc_perm_access, "ipc_perm", process_kobject, "process", ipc_kobject, "object");

int __init ipc_acctype_init(void) {
	MED_REGISTER_ACCTYPE(ipc_perm_access,MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_ipc_perm_pacb(struct audit_buffer *ab, void *pcad);
/*
 * Check permissions for access to IPC
 * @ipcp contains the kernel IPC permission structure
 * @perm contains the desired (requested) permission set
 *
 * This function is called with rcu_read_lock(), but sometimes with
 * ipcp->lock held :(
 *
 * security_ipc_permission()
 *  |
 *  |<-- ipcperms()
 *        |
 *        |<-- !!! ipc_check_perms() !!!
 *        |        this routine is called by sys_msgget(), sys_semget(), sys_shmget()
 *        |        when the key is not IPC_PRIVATE and exists in the ds IDR;
 *        |        it is always called with ipcp->lock held
 *        |
 *        |<-- !!! do_msgsnd() !!! (due to crappy implementation always get ipcp->lock)
 *        |<-- do_msgrcv()
 *        |<-- msgctl_stat()
 *        |
 *        |<-- do_shmat()
 *        |<-- shmctl_stat()
 *        |
 *        |<-- do_semtimedop()
 *        |<-- semctl_main()
 *        |<-- semctl_stat()
 *        |<-- semctl_setval()
 */
medusa_answer_t medusa_ipc_permission(struct kern_ipc_perm *ipcp, u32 perms)
{
	medusa_answer_t retval = MED_ALLOW;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .event = EVENT_MONITORED_N, .pacb.ipc_perm.ipc_class = MED_IPC_UNDEFINED };
	struct ipc_perm_access access;
	struct process_kobject process;
	struct ipc_kobject object;
	bool use_locking = false;

#ifdef CONFIG_SMP
	/*
	 * WORKAROUND!!!
	 *
	 * An IPC object enters this call in different conditions: sometimes its
	 * spinlock is held, sometimes not. This behaviour is crazy because
	 * it is not possible to implement one simple code path (with regard to
	 * implementation of spinlocks)...
	 *
	 * If a spinlock is locked, we need to determine the owner of this spinlock.
	 * Spinlock can be locked by our process, but also from another (concurrently
	 * running) part(s) of IPC subsystem, and this is indistinguishable without
	 * CONFIG_DEBUG_SPINLOCK turned on.
	 *
	 * Note: On UP spins doesn't exist, lucky us ;)
	 *       Medusa on UP always can make a decision without a carry on spinlocks...
	 */

	if (spin_is_locked(&(ipcp->lock))) {
#ifdef CONFIG_DEBUG_SPINLOCK
		/*
		 * If current process is holding the spinlock, we need to unlock it;
		 * otherwise another process is holding the spinlock, we don't touch it.
		 *
		 * It is not necessary to check rlock.owner_cpu == raw_smp_processor_id(),
		 * because if current process is holding the spinlock, that spinlock
		 * was taken in currently running RCU, so there is no possibility to
		 * reschedule.
		 */
		if (ipcp->lock.rlock.owner == current)
			use_locking = true;
#else /* !CONFIG_DEBUG_SPINLOCK */
		/*
		 * If CONFIG_DEBUG_SPINLOCK is off and a spinlock is held, there is no
		 * possibility to determine the owner of this spinlock. So we cannot
		 * determine, whether the spinlock can be or not (un)locked.
		 *
		 * We should return MED_ERR, because Medusa subsystem can't make a decision,
		 * but this value has to be converted to MED_ALLOW, so function directly
		 * returns MED_ALLOW.
		 *
		 * Note:
		 * Yes, due to nondeterministic behaviour of IPC object's spinlock
		 * in this function this way we lose do_msgsnd() and ipc_check_perms()
		 * controls...
		 */
		return retval;
#endif /* CONFIG_DEBUG_SPINLOCK */
	}
#endif /* CONFIG_SMP */

	/*
	 * Increase references to the IPC object; second argument:
	 *   true - returns with unlocked IPC object
	 *   false - don't need to unlock IPC object
	 */
	if (unlikely(ipc_getref(ipcp, use_locking)))
		/* for now, we don't support error codes */
		return MED_DENY;
	if (!is_med_magic_valid(&(task_security(current)->med_object)) && process_kobj_validate_task(current) <= 0)
		goto out;
	if (!is_med_magic_valid(&(ipc_security(ipcp)->med_object)) && ipc_kobj_validate_ipcp(ipcp) <= 0)
		goto out;

	cad.type = LSM_AUDIT_DATA_IPC;
	cad.u.ipc_id = ipcp->key;

	if (MEDUSA_MONITORED_ACCESS_S(ipc_perm_access, task_security(current))) {
		mad.event = EVENT_MONITORED;
		process_kern2kobj(&process, current);
		/* 3-th argument is true: decrement IPC object's refcount in returned object */
		if (ipc_kern2kobj(&object, ipcp, true) == NULL)
			goto audit;

		memset(&access, '\0', sizeof(struct ipc_perm_access));
		access.perms = perms;
		access.ipc_class = object.ipc_class;
		mad.pacb.ipc_perm.ipc_class = object.ipc_class;

		retval = MED_DECIDE(ipc_perm_access, &access, &process, &object);
		if (retval == MED_ERR)
			retval = MED_ALLOW;
	}
audit:
	if (unlikely(ipc_putref(ipcp, use_locking)))
		/* for now, we don't support error codes */
		retval = MED_DENY;
#ifdef CONFIG_AUDIT
	mad.function = __func__;
	mad.med_answer = retval;
	mad.pacb.ipc_perm.r_perm = perms;
	cad.medusa_audit_data = &mad;
	medusa_audit_log_callback(&cad, medusa_ipc_perm_pacb);
#endif
	return retval;
out:
	/*
	 * Decrease references to the IPC object; second argument:
	 *   true - returns with locked IPC object
	 *   false - don't need to lock IPC object
	 */
	if (unlikely(ipc_putref(ipcp, use_locking)))
		/* for now, we don't support error codes */
		retval = MED_DENY;
	return retval;
}

static void medusa_ipc_perm_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if ((&(mad->pacb.ipc_perm))->r_perm) {
		audit_log_format(ab," perm=%u",((&(mad->pacb.ipc_perm))->r_perm));
	}
	if ((&(mad->pacb.ipc_perm))->ipc_class) {
		audit_log_format(ab," ipc_class=%u",((&(mad->pacb.ipc_perm))->ipc_class));
	}
}
__initcall(ipc_acctype_init);

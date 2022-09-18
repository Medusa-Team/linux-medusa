// SPDX-License-Identifier: GPL-2.0-only

/*
 * IPC permission access type implementation.
 *
 * Copyright (C) 2017-2018 Viliam Mihalik
 * Copyright (C) 2018-2020 Matus Jokay
 */

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_ipc.h"
#include "l2/l2.h"
#include "l2/audit_medusa.h"

struct ipc_perm_access {
	MEDUSA_ACCESS_HEADER;
	unsigned int ipc_class;
	u32 perms;		/* desired (requested) permission set */
};

MED_ATTRS(ipc_perm_access) {
	MED_ATTR_RO(ipc_perm_access, perms, "perms", MED_UNSIGNED),
	MED_ATTR_RO(ipc_perm_access, ipc_class, "ipc_class", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(ipc_perm_access, "ipc_perm", process_kobject, "process", ipc_kobject, "object");

int __init ipc_acctype_perm_init(void)
{
	MED_REGISTER_ACCTYPE(ipc_perm_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_ipc_perm_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if (mad->pacb.ipc_perm.perms)
		audit_log_format(ab," perms=%u", mad->pacb.ipc_perm.perms);
	if (mad->pacb.ipc_perm.ipc_class)
		audit_log_format(ab," ipc_class=%u", mad->pacb.ipc_perm.ipc_class);
}

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
int medusa_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	int retval;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .event = EVENT_MONITORED_N, .pacb.ipc_perm.ipc_class = MED_IPC_UNDEFINED };
	enum medusa_answer_t ans = MED_ALLOW;
	struct ipc_perm_access access;
	struct process_kobject process;
	struct ipc_kobject object;
	bool __maybe_unused use_locking = false;
	int err = 0;

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
	if (IS_ENABLED(CONFIG_SMP) && spin_is_locked(&(ipcp->lock))) {
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
#else
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
		return lsm_retval(ans, err);
#endif
	}

	/*
	 * Increase references to the IPC object; second argument:
	 *   true - returns with unlocked IPC object
	 *   false - don't need to unlock IPC object
	 */
	if (unlikely((err = ipc_getref(ipcp, use_locking)) != 0))
		/* ipc_getref() returns -EIDRM if IPC object is marked to deletion */
		return err;

	if (!is_med_magic_valid(&(task_security(current)->med_object))
	    && process_kobj_validate_task(current) <= 0)
		goto out;
	if (!is_med_magic_valid(&(ipc_security(ipcp)->med_object))
	    && ipc_kobj_validate_ipcp(ipcp) <= 0)
		goto out;

	if (MEDUSA_MONITORED_ACCESS_O(ipc_perm_access, ipc_security(ipcp))) {
		mad.event = EVENT_MONITORED;
		process_kern2kobj(&process, current);
		/* 3-th argument is true: decrement IPC object's refcount in returned object */
		ipc_kern2kobj(&object, ipcp, true);

		access.perms = flag;
		access.ipc_class = object.ipc_class;
		mad.pacb.ipc_perm.ipc_class = object.ipc_class;

		ans = MED_DECIDE(ipc_perm_access, &access, &process, &object);
	}
out:
	/*
	 * Decrease references to the IPC object; second argument:
	 *   true - returns with locked IPC object
	 *   false - don't need to lock IPC object
	 */
	/* second argument true: returns with locked IPC object */
	err = ipc_putref(ipcp, use_locking);
	retval = lsm_retval(ans, err);
#ifdef CONFIG_AUDIT
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_IPC;
		cad.u.ipc_id = ipcp->key;
		mad.function = "ipc_permission";
		mad.med_answer = retval;
		mad.pacb.ipc_perm.perms = flag;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_ipc_perm_pacb);
	}
#endif
	return retval;
}

device_initcall(ipc_acctype_perm_init);

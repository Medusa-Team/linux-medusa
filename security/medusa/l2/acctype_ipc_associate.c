// SPDX-License-Identifier: GPL-2.0-only
/*
 * security/medusa/l2/acctype_ipc_associate.c
 *
 * IPC associate access type implementation.
 *
 * Copyright (C) 2017-2018 Viliam Mihalik
 * Copyright (C) 2018-2020 Matus Jokay
 */

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_ipc.h"

struct ipc_associate_access {
	MEDUSA_ACCESS_HEADER;
	int flag;		/* operation control flags */
	unsigned int ipc_class;
};

MED_ATTRS(ipc_associate_access) {
	MED_ATTR_RO(ipc_associate_access, flag, "flag", MED_SIGNED),
	MED_ATTR_RO(ipc_associate_access, ipc_class, "ipc_class", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(ipc_associate_access, "ipc_associate", process_kobject, "process", ipc_kobject, "object");

int __init ipc_acctype_associate_init(void)
{
	MED_REGISTER_ACCTYPE(ipc_associate_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* Check permission when
 *	1) a message queue is requested through the msgget system call
 *	2) a shared memory region is requested through the shmget system call
 *	3) a semaphore is requested through the semget system call
 * This hook is only called when returning the identifier for an existing IPC
 * object (when the key is not IPC_PRIVATE), not when a new one must be created!
 * @ipcp contains kernel permission IPC structure
 * @flag contains the operation control flags
 *
 * This routine is called only by ipc_check_perms() (ipc/util.c)
 * always with ipc_ids.rwsem and ipcp->lock held, so we need to unlock the
 * spinlock before waiting.
 *
 * security_[sem|shm|msg]_associate()
 *  |
 *  |<-- ipc_check_perms()
 *       this routine is called by sys_msgget(), sys_semget(), sys_shmget()
 *       when the key is not IPC_PRIVATE and exists in the ds IDR
 *       is always called with ipcp->lock held
 *
 */
enum medusa_answer_t medusa_ipc_associate(struct kern_ipc_perm *ipcp, int flag)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct ipc_associate_access access;
	struct process_kobject process;
	struct ipc_kobject object;

	/* second argument true: returns with unlocked IPC object */
	if (unlikely(ipc_getref(ipcp, true)))
		/* for now, we don't support error codes */
		return MED_DENY;

	if (!is_med_magic_valid(&(task_security(current)->med_object))
	    && process_kobj_validate_task(current) <= 0)
		goto out;
	if (!is_med_magic_valid(&(ipc_security(ipcp)->med_object))
	    && ipc_kobj_validate_ipcp(ipcp) <= 0)
		goto out;

	if (!vs_intersects(VSS(task_security(current)), VS(ipc_security(ipcp)))
	    || !vs_intersects(VSW(task_security(current)), VS(ipc_security(ipcp)))
	) {
		retval = MED_DENY;
		goto out;
	}

	if (MEDUSA_MONITORED_ACCESS_O(ipc_associate_access, ipc_security(ipcp))) {
		process_kern2kobj(&process, current);
		/* 3-th argument is true: decrement IPC object's refcount in returned object */
		if (ipc_kern2kobj(&object, ipcp, true) == NULL)
			goto out;

		memset(&access, '\0', sizeof(struct ipc_associate_access));
		access.flag = flag;
		access.ipc_class = object.ipc_class;

		retval = MED_DECIDE(ipc_associate_access, &access, &process, &object);
	}
out:
	/* second argument true: returns with locked IPC object */
	if (unlikely(ipc_putref(ipcp, true)))
		/* for now, we don't support error codes */
		retval = MED_DENY;
	return retval;
}

device_initcall(ipc_acctype_associate_init);

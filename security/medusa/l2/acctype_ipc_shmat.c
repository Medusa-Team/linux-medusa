// SPDX-License-Identifier: GPL-2.0-only
/*
 * security/medusa/l2/acctype_ipc_shmat.c
 *
 * IPC shmat access type implementation.
 *
 * Copyright (C) 2017-2018 Viliam Mihalik
 * Copyright (C) 2018-2020 Matus Jokay
 */

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_ipc.h"

struct ipc_shmat_access {
	MEDUSA_ACCESS_HEADER;
	char __user *shmaddr;	/* address to attach memory region to */
	int shmflg;		/* operational flags */
	unsigned int ipc_class;
};

MED_ATTRS(ipc_shmat_access) {
	MED_ATTR_RO(ipc_shmat_access, shmflg, "shmflg", MED_SIGNED),
	MED_ATTR_RO(ipc_shmat_access, shmaddr, "shmaddr", MED_UNSIGNED),
	MED_ATTR_RO(ipc_shmat_access, ipc_class, "ipc_class", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(ipc_shmat_access, "ipc_shmat", process_kobject, "process", ipc_kobject, "object");

int __init ipc_acctype_shmat_init(void)
{
	MED_REGISTER_ACCTYPE(ipc_shmat_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/*
 * Check permissions prior to allowing the shmat system call to attach the
 * shared memory segment with given ipc_perm @ipcp to the data segment of
 * the calling process. The attaching address is specified by @shmaddr
 * @ipcp contains shared memory segment ipc_perm structure
 * @shmaddr contains the address to attach memory region to
 * @shmflag contains the operational flags
 *
 * This routine is called only by do_shmat() (ipc/shm.c) in RCU read-side.
 *
 * security_shm_shmat()
 *  |
 *  |<-- do_shmat()
 */
enum medusa_answer_t medusa_ipc_shmat(struct kern_ipc_perm *ipcp,
				 char __user *shmaddr, int shmflg)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct ipc_shmat_access access;
	struct process_kobject process;
	struct ipc_kobject object;

	/* second argument false: don't need to unlock IPC object */
	if (unlikely(ipc_getref(ipcp, false)))
		/* for now, we don't support error codes */
		return MED_DENY;

	if (!is_med_magic_valid(&(task_security(current)->med_object))
	    && process_kobj_validate_task(current) <= 0)
		goto out;
	if (!is_med_magic_valid(&(ipc_security(ipcp)->med_object))
	    && ipc_kobj_validate_ipcp(ipcp) <= 0)
		goto out;

	if (MEDUSA_MONITORED_ACCESS_O(ipc_shmat_access, ipc_security(ipcp))) {
		process_kern2kobj(&process, current);
		/* 3-th argument is true: decrement IPC object's refcount in returned object */
		if (ipc_kern2kobj(&object, ipcp, true) == NULL)
			goto out;

		memset(&access, '\0', sizeof(struct ipc_shmat_access));
		access.shmflg = shmflg;
		access.shmaddr = shmaddr;
		access.ipc_class = object.ipc_class;

		retval = MED_DECIDE(ipc_shmat_access, &access, &process, &object);
	}
out:
	/* second argument false: don't need to lock IPC object */
	if (unlikely(ipc_putref(ipcp, false)))
		/* for now, we don't support error codes */
		retval = MED_DENY;
	return retval;
}

device_initcall(ipc_acctype_shmat_init);

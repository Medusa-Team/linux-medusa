// SPDX-License-Identifier: GPL-2.0-only

/*
 * IPC associate access type implementation.
 *
 * Copyright (C) 2017-2018 Viliam Mihalik
 * Copyright (C) 2018-2020 Matus Jokay
 */

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_ipc.h"
#include "l2/l2.h"
#include "l2/audit_medusa.h"

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

static void medusa_ipc_associate_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if (mad->pacb.ipc.flcm)
		audit_log_format(ab," flag=%d", mad->pacb.ipc.flcm);
	if (mad->pacb.ipc.ipc_class)
		audit_log_format(ab," ipc_class=%u", mad->pacb.ipc.ipc_class);
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
int medusa_ipc_associate(struct kern_ipc_perm *ipcp, int flag, char *operation)
{
	int retval;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .vsi = VS_SW_N, .pacb.ipc.ipc_class = MED_IPC_UNDEFINED };
	enum medusa_answer_t ans = MED_ALLOW;
	struct ipc_associate_access access;
	struct process_kobject process;
	struct ipc_kobject object;
	int err = 0;

	/* second argument true: returns with unlocked IPC object */
	if (unlikely((err = ipc_getref(ipcp, true)) != 0))
		/* ipc_getref() returns -EIDRM if IPC object is marked to deletion */
		return err;

	if (!is_med_magic_valid(&(task_security(current)->med_object))
	    && process_kobj_validate_task(current) <= 0)
		goto out;
	if (!is_med_magic_valid(&(ipc_security(ipcp)->med_object))
	    && ipc_kobj_validate_ipcp(ipcp) <= 0)
		goto out;

	if (!vs_intersects(VSS(task_security(current)), VS(ipc_security(ipcp)))
	    || !vs_intersects(VSW(task_security(current)), VS(ipc_security(ipcp)))
	) {
		mad.vs.sw.vst = VS(ipc_security(ipcp));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		ans = MED_DENY;
		goto out;
	} else {
 		mad.vsi = VS_INTERSECT;
	}

	if (MEDUSA_MONITORED_ACCESS_O(ipc_associate_access, ipc_security(ipcp))) {
		mad.event = EVENT_MONITORED;
		process_kern2kobj(&process, current);
		/* 3-th argument is true: decrement IPC object's refcount in returned object */
		ipc_kern2kobj(&object, ipcp, true);

		memset(&access, '\0', sizeof(struct ipc_associate_access));
		access.flag = flag;
		access.ipc_class = object.ipc_class;
		mad.pacb.ipc.ipc_class = object.ipc_class;

		ans = MED_DECIDE(ipc_associate_access, &access, &process, &object);
	} else {
		mad.event = EVENT_MONITORED_N;
	}
out:
	/* second argument true: returns with locked IPC object */
	err = ipc_putref(ipcp, true);
	retval = lsm_retval(ans, err);
#ifdef CONFIG_AUDIT
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_IPC;
		cad.u.ipc_id = ipcp->key;
		mad.function = operation;
		mad.med_answer = retval;
		mad.pacb.ipc.flcm = flag;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_ipc_associate_pacb);
	}
#endif
	return retval;
}

device_initcall(ipc_acctype_associate_init);

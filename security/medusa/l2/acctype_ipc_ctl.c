// SPDX-License-Identifier: GPL-2.0-only

/*
 * IPC ctl access type implementation.
 *
 * Copyright (C) 2017-2018 Viliam Mihalik
 * Copyright (C) 2018-2020 Matus Jokay
 */

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_ipc.h"
#include "l2/l2.h"
#include "l2/audit_medusa.h"

struct ipc_ctl_access {
	MEDUSA_ACCESS_HEADER;
	int cmd;		/* operation to be performed */
	unsigned int ipc_class;
};

MED_ATTRS(ipc_ctl_access) {
	MED_ATTR_RO(ipc_ctl_access, cmd, "cmd", MED_SIGNED),
	MED_ATTR_RO(ipc_ctl_access, ipc_class, "ipc_class", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(ipc_ctl_access, "ipc_ctl", process_kobject, "process", ipc_kobject, "object");

int __init ipc_acctype_ctl_init(void)
{
	MED_REGISTER_ACCTYPE(ipc_ctl_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_ipc_ctl_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if (mad->pacb.ipc.flcm)
		audit_log_format(ab," cmd=%d", mad->pacb.ipc.flcm);
	if (mad->pacb.ipc.ipc_class)
		audit_log_format(ab," ipc_class=%u", mad->pacb.ipc.ipc_class);
}

/*
 * Check permission when an IPC object (semaphore, message queue, shared memory)
 * operation specified by @cmd is to be performed on the IPC object for which
 * kernel ipc permission @ipcp is given. The @ipcp may be NULL, e.g. for
 * IPC_INFO or MSG_INFO or SEM_INFO or SHM_INFO @cmd value.
 * @ipcp contains kernel IPC permission of the related IPC object
 * @cmd contains the operation to be performed
 *
 * This function is called with rcu_read_lock() held if @ipcp is not NULL.
 * So in this case it is necessary to release rcu lock because
 * this routine may wait while authorisation server is deciding.
 *
 * medusa_ipc_ctl()
 *  |
 *  |<-- medusa_l1_msg_queue_msgctl()
 *  |     |
 *  |     |<-- security_msg_queue_msgctl()
 *  |           |
 *  |           |<-- msgctl_stat()
 *  |           |<-- msgctl_down()
 *  |           |<-- msgctl_info() (@ipcp is NULL, no rcu_read_lock())
 *  |
 *  |<-- medusa_l1_sem_semctl()
 *  |     |
 *  |     |<-- security_sem_semctl()
 *  |           |
 *  |           |<-- semctl_stat()
 *  |           |<-- semctl_down()
 *  |           |<-- semctl_setval()
 *  |           |<-- semctl_main()
 *  |           |<-- semctl_info() (@ipcp is NULL, no rcu_read_lock())
 *  |
 *  |<-- medusa_l1_shm_shmctl()
 *        |
 *        |<-- security_shm_shmctl()
 *              |
 *              |<-- shmctl_stat()
 *              |<-- shmctl_down()
 *              |<-- shmctl_do_lock()
 *              |<-- shmctl_shm_info() (@ipcp is NULL, no rcu_read_lock())
 *              |<-- shmctl_ipc_info() (@ipcp is NULL, no rcu_read_lock())
 */
int medusa_ipc_ctl(struct kern_ipc_perm *ipcp, int cmd, char *operation)
{
	int retval;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .event = EVENT_MONITORED_N, .pacb.ipc.ipc_class = MED_IPC_UNDEFINED };
	enum medusa_answer_t ans = MED_ALLOW;
	struct ipc_ctl_access access;
	struct process_kobject process;
	struct ipc_kobject object, *object_p = NULL;
	int err = 0;

	/* 'ipcp' is NULL in case of 'cmd': IPC_INFO, MSG_INFO, SEM_INFO, SHM_INFO */
	if (likely(ipcp)) {
		/* second argument false: don't need to unlock IPC object */
		if (unlikely((err = ipc_getref(ipcp, false)) != 0))
			/* ipc_getref() returns -EIDRM if IPC object is marked to deletion */
			return err;

		object_p = &object;
		if (!is_med_magic_valid(&(ipc_security(ipcp)->med_object))
		    && ipc_kobj_validate_ipcp(ipcp) <= 0)
			goto out;
	}

	if (!is_med_magic_valid(&(task_security(current)->med_object))
	    && process_kobj_validate_task(current) <= 0)
		goto out;

	if (MEDUSA_MONITORED_ACCESS_O(ipc_ctl_access, ipc_security(ipcp))) {
		mad.event = EVENT_MONITORED;
		memset(&access, '\0', sizeof(struct ipc_ctl_access));
		access.cmd = cmd;
		access.ipc_class = MED_IPC_UNDEFINED;

		process_kern2kobj(&process, current);
		if (likely(object_p)) {
			/* 3-th argument is true: decrement IPC object's refcount in returned object */
			ipc_kern2kobj(object_p, ipcp, true);
			access.ipc_class = object_p->ipc_class;
			mad.pacb.ipc.ipc_class = object_p->ipc_class;
		}

		/* in case of NULL 'ipcp', 'object_p' is NULL too */
		ans = MED_DECIDE(ipc_ctl_access, &access, &process, object_p);
	}
out:
	if (likely(ipcp)) {
		/* second argument false: don't need to lock IPC object */
		err = ipc_putref(ipcp, false);
	}
	retval = lsm_retval(ans, err);
#ifdef CONFIG_AUDIT
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_IPC;
		cad.u.ipc_id = ipcp->key;
		mad.function = operation;
		mad.med_answer = retval;
		mad.pacb.ipc.flcm = cmd;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_ipc_ctl_pacb);
	}
#endif
	return retval;
}

device_initcall(ipc_acctype_ctl_init);

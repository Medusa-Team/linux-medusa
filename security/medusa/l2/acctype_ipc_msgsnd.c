// SPDX-License-Identifier: GPL-2.0-only

/*
 * IPC msgsnd access type implementation.
 *
 * Copyright (C) 2017-2018 Viliam Mihalik
 * Copyright (C) 2018-2020 Matus Jokay
 */

#include <linux/msg.h>
#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_ipc.h"

/*
 * struct @ipc_msgsnd_access is derived from 'struct msg_msg' in include/linux/msg.h
 * and does NOT contain all attributes from original 'struct msg_msg'
 * @m_type - message type
 * @m_ts - message text size
 * @msgflg - operation flags
 * @ipc_class - type of System V ipc (shm, semaphor .. )
 */
struct ipc_msgsnd_access {
	MEDUSA_ACCESS_HEADER;
	long m_type;
	size_t m_ts;
	int msgflg;
	unsigned int ipc_class;
};

MED_ATTRS(ipc_msgsnd_access) {
	MED_ATTR_RO(ipc_msgsnd_access, m_type, "m_type", MED_SIGNED),
	MED_ATTR_RO(ipc_msgsnd_access, m_ts, "m_ts", MED_UNSIGNED),
	MED_ATTR_RO(ipc_msgsnd_access, msgflg, "msgflg", MED_SIGNED),
	MED_ATTR_RO(ipc_msgsnd_access, ipc_class, "ipc_class", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(ipc_msgsnd_access, "ipc_msgsnd", process_kobject, "process", ipc_kobject, "object");

int __init ipc_acctype_msgsnd_init(void)
{
	MED_REGISTER_ACCTYPE(ipc_msgsnd_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/*
 * Check permission before a message @msg is enqueued on the message queue for
 * which kernel ipc permission @ipcp is given.
 * @ipcp contains kernel ipc permissions for related message queue
 * @msg contains the message to be enqueued
 * @msgflg contains the operational flags
 *
 * This function is always called with rcu_read_lock() and ipcp->lock held.
 *
 * security_msg_queue_msgsnd()
 *  |
 *  |<-- do_msgsnd() (always get ipcp->lock)
 */
enum medusa_answer_t medusa_ipc_msgsnd(struct kern_ipc_perm *ipcp,
				  struct msg_msg *msg, int msgflg)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct ipc_msgsnd_access access;
	struct process_kobject process;
	struct ipc_kobject object;

	/* second argument true: returns with unlocked IPC object */
	if (unlikely(ipc_getref(ipcp, true)))
		/*
		 * ipc_getref() returns -EIDRM if IPC object is marked to deletion,
		 * so deny any operation on it.
		 */
		return MED_DENY;

	if (!is_med_magic_valid(&(task_security(current)->med_object))
	    && process_kobj_validate_task(current) <= 0)
		goto out;
	if (!is_med_magic_valid(&(ipc_security(ipcp)->med_object))
	    && ipc_kobj_validate_ipcp(ipcp) <= 0)
		goto out;

	if (MEDUSA_MONITORED_ACCESS_O(ipc_msgsnd_access, ipc_security(ipcp))) {
		process_kern2kobj(&process, current);
		/* 3-th argument is true: decrement IPC object's refcount in returned object */
		ipc_kern2kobj(&object, ipcp, true);

		access.m_type = msg->m_type;
		access.m_ts = msg->m_ts;
		access.msgflg = msgflg;
		access.ipc_class = object.ipc_class;

		retval = MED_DECIDE(ipc_msgsnd_access, &access, &process, &object);
	}
out:
	/* second argument true: returns with locked IPC object */
	if (unlikely(ipc_putref(ipcp, true)))
		/* for now, we don't support error codes */
		retval = MED_DENY;
	return retval;
}

device_initcall(ipc_acctype_msgsnd_init);

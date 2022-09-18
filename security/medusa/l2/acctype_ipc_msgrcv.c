// SPDX-License-Identifier: GPL-2.0-only

/*
 * IPC msgrcv access type implementation.
 *
 * Copyright (C) 2017-2018 Viliam Mihalik
 * Copyright (C) 2018-2020 Matus Jokay
 */

#include <linux/msg.h>
#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_ipc.h"
#include "l2/l2.h"
#include "l2/audit_medusa.h"

struct ipc_msgrcv_access {
	MEDUSA_ACCESS_HEADER;
	long m_type;	/* message type; see 'struct msg_msg' in include/linux/msg.h */
	size_t m_ts;	/* msg text size; see 'struct msg_msg' in include/linux/msg.h */
	/* char m_text[???]; message text is not sent, for now */
	pid_t target;	/* TODO: namespaces implementation */
	long type;	/* type of requested message */
	int mode;	/* operational flags */
	unsigned int ipc_class;
};

MED_ATTRS(ipc_msgrcv_access) {
	MED_ATTR_RO(ipc_msgrcv_access, m_type, "m_type", MED_SIGNED),
	MED_ATTR_RO(ipc_msgrcv_access, m_ts, "m_ts", MED_UNSIGNED),
	MED_ATTR_RO(ipc_msgrcv_access, target, "target", MED_SIGNED),
	MED_ATTR_RO(ipc_msgrcv_access, type, "type", MED_SIGNED),
	MED_ATTR_RO(ipc_msgrcv_access, mode, "mode", MED_SIGNED),
	MED_ATTR_RO(ipc_msgrcv_access, ipc_class, "ipc_class", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(ipc_msgrcv_access, "ipc_msgrcv", process_kobject, "process", ipc_kobject, "object");

int __init ipc_acctype_msgrcv_init(void)
{
	MED_REGISTER_ACCTYPE(ipc_msgrcv_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_ipc_msgrcv_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if (mad->pacb.ipc_msg.flag)
		audit_log_format(ab," flag=%d", mad->pacb.ipc_msg.flag);
	if (mad->pacb.ipc_msg.m_type)
		audit_log_format(ab," m_type=%ld", mad->pacb.ipc_msg.m_type);
	if (mad->pacb.ipc_msg.m_ts)
		audit_log_format(ab," m_ts=%lu", mad->pacb.ipc_msg.m_ts);
	if (mad->pacb.ipc_msg.type)
		audit_log_format(ab," rm_type=%ld", mad->pacb.ipc_msg.type);
	if (mad->pacb.ipc_msg.target)
		audit_log_format(ab," opid=%d", mad->pacb.ipc_msg.target);
	if (mad->pacb.ipc_msg.ipc_class)
		audit_log_format(ab," ipc_class=%u", mad->pacb.ipc_msg.ipc_class);
}

/*
 * Check permission before a message @msg is removed from the message queue,
 * for which kernel permission structure @ipcp is given. The @target task
 * structure contains a pointer to the process that will be receiving the
 * message (not equal to the current process when inline receives are being
 * performed).
 * @ipcp contains kernel permission structure for message queue
 * @msg contains the message destination
 * @target contains the task structure for recipient process
 * @type contains the type of message requested
 * @mode contains the operational flags
 *
 * This function is always called with rcu_read_lock() and ipcp->lock held.
 *
 * security_msg_queue_msgrcv()
 *  |
 *  |<-- pipelined_send()
 *  |     |
 *  |     |<-- do_msgsnd() (always get ipcp->lock)
 *  |
 *  |<-- find_msg()
 *        |
 *        |<-- do_msgrcv() (always get ipcp->lock)
 */
int medusa_ipc_msgrcv(struct kern_ipc_perm *ipcp,
		      struct msg_msg *msg,
		      struct task_struct *target,
		      long type,
		      int mode)
{
	int retval;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .event = EVENT_MONITORED_N, .pacb.ipc_msg.ipc_class = MED_IPC_UNDEFINED };
	enum medusa_answer_t ans = MED_ALLOW;
	struct ipc_msgrcv_access access;
	struct process_kobject process;
	struct ipc_kobject object;
	int err = 0;

	/* Access to the @msg should be done with locked IPC object @ipcp due to
	 * race with freeque(), so fill related access structure fields before
	 * unlocking the IPC object in ipc_getref().
	 */
	access.m_type = msg->m_type;
	access.m_ts = msg->m_ts;

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

	if (MEDUSA_MONITORED_ACCESS_O(ipc_msgrcv_access, ipc_security(ipcp))) {
		mad.event = EVENT_MONITORED;
		process_kern2kobj(&process, current);
		/* 3-th argument is true: decrement IPC object's refcount in returned object */
		ipc_kern2kobj(&object, ipcp, true);

		access.type = type;
		access.mode = mode;
		access.target = target->pid;
		access.ipc_class = object.ipc_class;
		mad.pacb.ipc_msg.ipc_class = object.ipc_class;

		ans = MED_DECIDE(ipc_msgrcv_access, &access, &process, &object);
	}
out:
	/* second argument true: returns with locked IPC object */
	err = ipc_putref(ipcp, true);
	retval = lsm_retval(ans, err);
#ifdef CONFIG_AUDIT
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_IPC;
		cad.u.ipc_id = ipcp->key;
		mad.function = "msgrcv";
		mad.med_answer = retval;
		mad.pacb.ipc_msg.m_type = msg->m_type;
		mad.pacb.ipc_msg.m_ts = msg->m_ts;
		mad.pacb.ipc_msg.flag = mode;
		mad.pacb.ipc_msg.type = type;
		mad.pacb.ipc_msg.target = target->pid;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_ipc_msgrcv_pacb);
	}
#endif
	return retval;
}

device_initcall(ipc_acctype_msgrcv_init);

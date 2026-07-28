// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_socket.h"
#include "l2/audit_medusa.h"

struct socket_recvmsg_access {
	MEDUSA_ACCESS_HEADER;
	int size;
	int flags;
};

MED_ATTRS(socket_recvmsg_access) {
	MED_ATTR_RO(socket_recvmsg_access, size, "size", MED_UNSIGNED),
	MED_ATTR_RO(socket_recvmsg_access, flags, "flags", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(socket_recvmsg_access, "socket_recvmsg_access",
	    process_kobject, "process",
	    socket_kobject, "socket");

static int __init socket_recvmsg_access_init(void)
{
	MED_REGISTER_ACCTYPE(socket_recvmsg_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

enum medusa_answer_t medusa_socket_recvmsg(struct socket *sock,
					   struct msghdr *msg,
					   int size,
					   int flags)
{
	struct socket_recvmsg_access access = {
		.size = size,
		.flags = flags,
	};
	struct process_kobject process;
	struct socket_kobject sock_kobj;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(socket_recvmsg_access))
		return MED_ALLOW;
	if (!is_med_magic_valid(&(sock_security(sock->sk)->med_object)) &&
	    socket_kobj_validate(sock) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(socket_recvmsg_access))
		return MED_ALLOW;

	if (!vs_intersects(VSS(task_security(current)), VS(sock_security(sock->sk))) ||
	    !vs_intersects(VSW(task_security(current)), VS(sock_security(sock->sk))))
		return MED_DENY;

	if (MEDUSA_MONITORED_ACCESS_S(socket_recvmsg_access, task_security(current))) {
		process_kern2kobj(&process, current);
		socket_kern2kobj(&sock_kobj, sock);

		return medusa_audit_decision_result(
			"socket_recvmsg",
			MED_DECIDE_RESULT(socket_recvmsg_access, &access,
					  &process, &sock_kobj),
			task_security(current)->audit);
	}
	return MED_ALLOW;
}

device_initcall(socket_recvmsg_access_init);

// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_socket.h"

struct socket_sendmsg_access {
	MEDUSA_ACCESS_HEADER;
	int size;
	int flags;
	int has_address;
	int addrlen;
	struct medusa_socket_address address;
};

MED_ATTRS(socket_sendmsg_access) {
	MED_ATTR_RO(socket_sendmsg_access, size, "size", MED_UNSIGNED),
	MED_ATTR_RO(socket_sendmsg_access, flags, "flags", MED_UNSIGNED),
	MED_ATTR_RO(socket_sendmsg_access, has_address, "has_address",
		    MED_UNSIGNED),
	MED_ATTR(socket_sendmsg_access, address, "address", MED_BYTES),
	MED_ATTR_RO(socket_sendmsg_access, addrlen, "addrlen", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(socket_sendmsg_access, "socket_sendmsg_access",
	    process_kobject, "process",
	    socket_kobject, "socket");

static int __init socket_sendmsg_access_init(void)
{
	MED_REGISTER_ACCTYPE(socket_sendmsg_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

enum medusa_answer_t medusa_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	struct socket_sendmsg_access access = {
		.size = size,
		.flags = msg->msg_flags,
	};
	struct process_kobject process;
	struct socket_kobject sock_kobj;
	int error;

	if (msg->msg_name) {
		error = medusa_socket_address_parse(&access.address,
						   msg->msg_name,
						   msg->msg_namelen);
		if (error == -EAFNOSUPPORT)
			return MED_ALLOW;
		if (error)
			return MED_ERR;
		access.has_address = 1;
		access.addrlen = msg->msg_namelen;
	}
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(socket_sendmsg_access))
		return MED_ALLOW;
	if (!is_med_magic_valid(&(sock_security(sock->sk)->med_object)) &&
	    socket_kobj_validate(sock) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(socket_sendmsg_access))
		return MED_ALLOW;

	if (!vs_intersects(VSS(task_security(current)), VS(sock_security(sock->sk))) ||
	    !vs_intersects(VSW(task_security(current)), VS(sock_security(sock->sk))))
		return MED_DENY;

	if (MEDUSA_MONITORED_ACCESS_S(socket_sendmsg_access, task_security(current))) {
		process_kern2kobj(&process, current);
		socket_kern2kobj(&sock_kobj, sock);

		return MED_DECIDE(socket_sendmsg_access, &access, &process, &sock_kobj);
	}
	return MED_ALLOW;
}

device_initcall(socket_sendmsg_access_init);

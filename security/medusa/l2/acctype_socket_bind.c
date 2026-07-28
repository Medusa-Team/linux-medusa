// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_socket.h"
#include "l2/audit_medusa.h"

struct socket_bind_access {
	MEDUSA_ACCESS_HEADER;
	sa_family_t family;
	int addrlen;
	struct medusa_socket_address address;
};

MED_ATTRS(socket_bind_access) {
	MED_ATTR_RO(socket_bind_access, family, "family", MED_UNSIGNED),
	MED_ATTR(socket_bind_access, address, "address", MED_BYTES),
	MED_ATTR_RO(socket_bind_access, addrlen, "addrlen", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(socket_bind_access, "socket_bind_access",
	    process_kobject, "process",
	    socket_kobject, "socket");

static int __init socket_bind_access_init(void)
{
	MED_REGISTER_ACCTYPE(socket_bind_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

static enum medusa_answer_t
medusa_socket_bind_security(struct socket *sock,
			    struct socket_bind_access *access)
{
	struct process_kobject process;
	struct socket_kobject sock_kobj;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(socket_bind_access))
		return MED_ALLOW;
	if (!is_med_magic_valid(&(sock_security(sock->sk)->med_object)) &&
	    socket_kobj_validate(sock) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(socket_bind_access))
		return MED_ALLOW;

	if (!vs_intersects(VSS(task_security(current)), VS(sock_security(sock->sk))) ||
	    !vs_intersects(VSW(task_security(current)), VS(sock_security(sock->sk))))
		return MED_DENY;

	if (MEDUSA_MONITORED_ACCESS_S(socket_bind_access, task_security(current))) {
		process_kern2kobj(&process, current);
		socket_kern2kobj(&sock_kobj, sock);
		return medusa_audit_decision_result(
			"socket_bind",
			MED_DECIDE_RESULT(socket_bind_access, access, &process,
					  &sock_kobj),
			task_security(current)->audit);
	}
	return medusa_audit_cached_allow("socket_bind",
					 task_security(current)->audit);
}

enum medusa_answer_t medusa_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct socket_bind_access access = {};
	int error;

	error = medusa_socket_address_parse(&access.address, address, addrlen);
	if (error == -EAFNOSUPPORT)
		return MED_ALLOW;
	if (error)
		return MED_ERR;

	access.family = access.address.family;
	access.addrlen = addrlen;
	return medusa_socket_bind_security(sock, &access);
}

device_initcall(socket_bind_access_init);

// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_socket.h"

struct socket_sendmsg_access {
	MEDUSA_ACCESS_HEADER;
	int addrlen;
	union MED_ADDRESS address;
};

MED_ATTRS(socket_sendmsg_access) {
	MED_ATTR(socket_sendmsg_access, address, "address", MED_BYTES),
	MED_ATTR_RO(socket_sendmsg_access, addrlen, "addrlen", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(socket_sendmsg_access, "socket_sendmsg_access", process_kobject, "process", socket_kobject, "socket");

int __init socket_sendmsg_access_init(void)
{
	MED_REGISTER_ACCTYPE(socket_sendmsg_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

enum medusa_answer_t medusa_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	int addrlen = msg->msg_namelen;
	void *address = msg->msg_name;
	struct socket_sendmsg_access access;
	struct process_kobject process;
	struct socket_kobject sock_kobj;

	if (!address || !sock->sk->sk_family)
		return MED_ALLOW;
	if (!is_med_magic_valid(&(task_security(current)->med_object)) && process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;
	if (!is_med_magic_valid(&(sock_security(sock->sk)->med_object)) && socket_kobj_validate(sock) <= 0)
		return MED_ALLOW;

	if (!vs_intersects(VSS(task_security(current)), VS(sock_security(sock->sk))) ||
		!vs_intersects(VSW(task_security(current)), VS(sock_security(sock->sk))))
		return MED_DENY;

	if (MEDUSA_MONITORED_ACCESS_S(socket_sendmsg_access, task_security(current))) {
		process_kern2kobj(&process, current);
		socket_kern2kobj(&sock_kobj, sock);
		switch (sock->sk->sk_family) {
		case AF_INET:
			if (addrlen < sizeof(struct sockaddr_in))
				return MED_ERR;
			access.address.inet_i.port = ((struct sockaddr_in *) address)->sin_port;
			memcpy(access.address.inet_i.addrdata, (__be32 *)&((struct sockaddr_in *) address)->sin_addr, 4);
			break;
		case AF_INET6:
			if (addrlen < SIN6_LEN_RFC2133)
				return MED_ERR;
			access.address.inet6_i.port = ((struct sockaddr_in6 *) address)->sin6_port;
			memcpy(access.address.inet6_i.addrdata, (__be32 *)((struct sockaddr_in6 *)address)->sin6_addr.s6_addr, 16);
			break;
		case AF_UNIX:
			memcpy(access.address.unix_i.addrdata, ((struct sockaddr_un *) address)->sun_path, UNIX_PATH_MAX);
			break;
		default:
			return MED_ALLOW;
		}

		return MED_DECIDE(socket_sendmsg_access, &access, &process, &sock_kobj);
	}
	return MED_ALLOW;
}

device_initcall(socket_sendmsg_access_init);

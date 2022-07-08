// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_socket.h"

struct socket_connect_access {
	MEDUSA_ACCESS_HEADER;
	sa_family_t family;
	int addrlen;
	union MED_ADDRESS address;
};

MED_ATTRS(socket_connect_access) {
	MED_ATTR_RO(socket_connect_access, family, "family", MED_UNSIGNED),
	MED_ATTR(socket_connect_access, address, "address", MED_BYTES),
	MED_ATTR_RO(socket_connect_access, addrlen, "addrlen", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(socket_connect_access, "socket_connect_access", process_kobject, "process", socket_kobject, "socket");

int __init socket_connect_access_init(void)
{
	MED_REGISTER_ACCTYPE(socket_connect_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}


enum medusa_answer_t medusa_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct socket_connect_access access;
	struct process_kobject process;
	struct socket_kobject sock_kobj;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) && process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;
	if (!is_med_magic_valid(&(sock_security(sock->sk)->med_object)) && socket_kobj_validate(sock) <= 0)
		return MED_ALLOW;

	if (!vs_intersects(VSS(task_security(current)), VS(sock_security(sock->sk))) ||
		!vs_intersects(VSW(task_security(current)), VS(sock_security(sock->sk))))
		return MED_DENY;

	if (MEDUSA_MONITORED_ACCESS_S(socket_connect_access, task_security(current))) {
		process_kern2kobj(&process, current);
		socket_kern2kobj(&sock_kobj, sock);
		access.family = address->sa_family;
		access.addrlen = addrlen;
		switch (address->sa_family) {
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

		return MED_DECIDE(socket_connect_access, &access, &process, &sock_kobj);
	}
	return MED_ALLOW;
}

device_initcall(socket_connect_access_init);

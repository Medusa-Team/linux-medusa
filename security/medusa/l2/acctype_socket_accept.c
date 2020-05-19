#include "kobject_process.h"
#include "kobject_socket.h"
#include "kobject_file.h"

struct socket_accept_access {
	MEDUSA_ACCESS_HEADER;

};

MED_ATTRS(socket_accept_access) {
	MED_ATTR_END
};

MED_ACCTYPE(socket_accept_access, "socket_accept_access", process_kobject, "process", socket_kobject, "socket");

int __init socket_accept_access_init(void) {
	MED_REGISTER_ACCTYPE(socket_accept_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

medusa_answer_t medusa_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct socket_accept_access access;
	struct process_kobject process;
	struct socket_kobject sock_kobj;
	medusa_answer_t retval;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) && process_kobj_validate_task(current) <= 0) {
		MEDUSAFS_RAISE_ALLOWED(socket_accept_access);
		return MED_ALLOW;
	}
	if (!is_med_magic_valid(&(sock_security(sock->sk)->med_object)) && socket_kobj_validate(sock) <= 0) {
		MEDUSAFS_RAISE_ALLOWED(socket_accept_access);
		return MED_ALLOW;
	}
	if (!vs_intersects(VSS(task_security(current)),VS(sock_security(sock->sk))) ||
		!vs_intersects(VSW(task_security(current)),VS(sock_security(sock->sk)))) {
		MEDUSAFS_RAISE_DENIED(socket_accept_access);
		return MED_DENY;
	}
	if (MEDUSA_MONITORED_ACCESS_S(socket_accept_access, task_security(current))) {
		socket_kern2kobj(&sock_kobj, sock);
		process_kern2kobj(&process, current);
		retval = MED_DECIDE(socket_accept_access, &access, &process, &sock_kobj);
		MEDUSAFS_RAISE_COUNTER(socket_accept_access);
		return retval;
	}
	MEDUSAFS_RAISE_ALLOWED(socket_accept_access);
	return MED_ALLOW;
}

__initcall(socket_accept_access_init);

#include "kobject_process.h"
#include "kobject_socket.h"
#include "kobject_file.h"

struct socket_listen_access {
	MEDUSA_ACCESS_HEADER;
	int backlog;
};

MED_ATTRS(socket_listen_access) {
	MED_ATTR_RO (socket_listen_access, backlog, "backlog", MED_SIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(socket_listen_access, "socket_listen_access", process_kobject, "process", socket_kobject, "socket");

int __init socket_listen_access_init(void) {
	MED_REGISTER_ACCTYPE(socket_listen_access, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

medusa_answer_t medusa_socket_listen(struct socket *sock, int backlog)
{
	struct socket_listen_access access;
	struct process_kobject process;
	struct socket_kobject sock_kobj;
	medusa_answer_t retval;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) && process_kobj_validate_task(current) <= 0) {
		MEDUSAFS_RAISE_ALLOWED(socket_listen_access);
		return MED_ALLOW;
	}
	if (!is_med_magic_valid(&(sock_security(sock->sk)->med_object)) && socket_kobj_validate(sock) <= 0) {
		MEDUSAFS_RAISE_ALLOWED(socket_listen_access);
		return MED_ALLOW;
	}
	if (!vs_intersects(VSS(task_security(current)),VS(sock_security(sock->sk))) ||
		!vs_intersects(VSW(task_security(current)),VS(sock_security(sock->sk)))) {
		MEDUSAFS_RAISE_DENIED(socket_listen_access);
		return MED_DENY;
	}
	if (MEDUSA_MONITORED_ACCESS_S(socket_listen_access, task_security(current))) {
		process_kern2kobj(&process, current);
		socket_kern2kobj(&sock_kobj, sock);
		access.backlog = backlog;
		retval = MED_DECIDE(socket_listen_access, &access, &process, &sock_kobj);
		MEDUSAFS_RAISE_COUNTER(socket_listen_access);
		return retval;
	}
	MEDUSAFS_RAISE_ALLOWED(socket_listen_access);
	return MED_ALLOW;
}

__initcall(socket_listen_access_init);

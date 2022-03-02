// SPDX-License-Identifier: GPL-2.0

#include "l3/registry.h"
#include "l2/kobject_socket.h"

struct socket_event {
	MEDUSA_ACCESS_HEADER;
};

MED_ATTRS(socket_event) {
	MED_ATTR_END
};

MED_EVTYPE(socket_event, "getsocket", socket_kobject, "socket", socket_kobject, "socket");

int __init socket_evtype_init(void)
{
	MED_REGISTER_EVTYPE(socket_event,
			MEDUSA_EVTYPE_TRIGGEREDATSUBJECT |
			MEDUSA_EVTYPE_TRIGGEREDBYOBJECTBIT |
			MEDUSA_EVTYPE_NOTTRIGGERED);
	return 0;
}

enum medusa_answer_t socket_kobj_validate(struct socket *sock)
{
	struct socket_event event;
	struct socket_kobject sock_kobj;
	struct medusa_l1_socket_s *sk_sec;

	/* nothing to do if there is no running authserver */
	if (!med_is_authserver_present())
		return 0;

	if (!sock->sk)
		return MED_ALLOW;

	sk_sec = sock_security(sock->sk);
	init_med_object(&(sk_sec->med_object));
	socket_kern2kobj(&sock_kobj, sock);

	if (MED_DECIDE(socket_event, &event, &sock_kobj, &sock_kobj) == MED_ERR)
		return MED_ERR;

	return MED_ALLOW;
}

device_initcall(socket_evtype_init);

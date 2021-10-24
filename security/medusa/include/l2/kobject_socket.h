/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _SOCKET_KOBJECT_H
#define _SOCKET_KOBJECT_H

#include <net/ipv6.h>
#include "l3/kobject.h"
#include "l1/socket.h"

struct socket_kobject {
	dev_t dev;
	unsigned long ino;

	int type;
	int family;
	int addrlen;
	union MED_ADDRESS address;
	kuid_t uid;

	struct medusa_object_s med_object;
};
extern MED_DECLARE_KCLASSOF(socket_kobject);

/* the conversion routines */
int socket_kobj2kern(struct socket_kobject *sock_kobj, struct socket *sock);
int socket_kern2kobj(struct socket_kobject *sock_kobj, struct socket *sock);

struct medusa_kobject_s *socket_fetch(struct medusa_kobject_s *kobj);
enum medusa_answer_t socket_update(struct medusa_kobject_s *kobj);

#endif

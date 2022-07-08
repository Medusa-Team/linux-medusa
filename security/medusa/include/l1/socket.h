/* SPDX-License-Identifier: GPL-2.0 */

/* (C) 2019 Michal Zelencik
 *
 * sock struct extension: this structure is appended to in-kernel data,
 * and we define it separately just to make l1 code shorter.
 *
 * for another data structure - kobject, describing socket for upper layers -
 * see security/medusa/l2/kobject_socket.[ch].
 */

#ifndef _MEDUSA_L1_SOCKET_H
#define _MEDUSA_L1_SOCKET_H

#include <uapi/linux/un.h> /* UNIX_PATH_MAX */
#include "l3/med_model.h"
#include "l3/constants.h"

#define sock_security(sk) ((struct medusa_l1_socket_s *)(sk->sk_security))

struct med_inet6_addr_i {
	__be16 port;
	__be32 addrdata[16];
};

struct med_inet_addr_i {
	__be16 port;
	__be32 addrdata[4];
};

struct med_unix_addr_i {
	char addrdata[UNIX_PATH_MAX];
};

union MED_ADDRESS {
	struct med_inet6_addr_i inet6_i;
	struct med_inet_addr_i inet_i;
	struct med_unix_addr_i unix_i;
};

/**
 * struct medusa_l1_socket_s - additional security struct for socket objects
 *
 * @struct medusa_object_s - members used in Medusa VS access evaluation process
 */
struct medusa_l1_socket_s {
	struct medusa_object_s med_object;
	int addrlen;
	union MED_ADDRESS address;
};

extern enum medusa_answer_t medusa_socket_create(int family, int type, int protocol);
extern enum medusa_answer_t medusa_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen);
extern enum medusa_answer_t medusa_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen);
extern enum medusa_answer_t medusa_socket_listen(struct socket *sock, int backlog);
extern enum medusa_answer_t medusa_socket_accept(struct socket *sock, struct socket *newsock);
extern enum medusa_answer_t medusa_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size);
extern enum medusa_answer_t medusa_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags);
/*
 * The following routine makes a support for many of access types,
 * and it is used both in L1 and L2 code. It is defined in
 * l2/evtype_getsocket.c.
 */
extern enum medusa_answer_t socket_kobj_validate(struct socket *sock);

#endif

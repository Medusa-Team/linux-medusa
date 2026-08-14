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

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/lsm_hooks.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <uapi/linux/un.h> /* UNIX_PATH_MAX */
#include "l3/med_model.h"
#include "l3/constants.h"

extern struct lsm_blob_sizes medusa_blob_sizes;

struct med_inet6_addr_i {
	__be16 port;
	__be32 flowinfo;
	struct in6_addr addr;
	__u32 scope_id;
};

struct med_inet_addr_i {
	__be16 port;
	struct in_addr addr;
};

struct med_unix_addr_i {
	__u8 addrdata[UNIX_PATH_MAX];
};

struct medusa_socket_address {
	sa_family_t family;
	__u16 data_length;
	__u32 addrlen;
	union {
		struct med_inet6_addr_i inet6;
		struct med_inet_addr_i inet;
		struct med_unix_addr_i unix_addr;
	} value;
};

/**
 * struct medusa_l1_socket_s - additional security struct for socket objects
 *
 * @struct medusa_object_s - members used in Medusa VS access evaluation process
 */
struct medusa_l1_socket_s {
	struct medusa_object_s med_object;
};

static inline struct medusa_l1_socket_s *sock_security(const struct sock *sk)
{
	return sk->sk_security + medusa_blob_sizes.lbs_sock;
}

static inline void
medusa_socket_context_init(struct medusa_l1_socket_s *context)
{
	init_med_object(&context->med_object);
}

static inline void
medusa_socket_context_clone(struct medusa_l1_socket_s *new_context,
			    const struct medusa_l1_socket_s *old_context)
{
	*new_context = *old_context;
}

int medusa_socket_address_parse(struct medusa_socket_address *destination,
				const struct sockaddr *address, int addrlen);

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

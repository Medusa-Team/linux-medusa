// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include "l3/registry.h"
#include "l2/kobject_socket.h"

MED_ATTRS(socket_kobject) {
	MED_ATTR_KEY_RO(socket_kobject, dev, "dev", MED_UNSIGNED),
	MED_ATTR_KEY_RO(socket_kobject, ino, "ino", MED_UNSIGNED),

	MED_ATTR_RO(socket_kobject, type, "type", MED_UNSIGNED),
	MED_ATTR_RO(socket_kobject, family, "family", MED_UNSIGNED),
	MED_ATTR_RO(socket_kobject, protocol, "protocol", MED_UNSIGNED),
	MED_ATTR_RO(socket_kobject, netns_cookie, "netns_cookie", MED_UNSIGNED),
	MED_ATTR(socket_kobject, uid, "uid", MED_UNSIGNED),
	MED_ATTR_OBJECT(socket_kobject),

	MED_ATTR_END
};

static inline int socket_kobj2kern(struct socket_kobject *sock_kobj, struct socket *sock)
{
	struct medusa_l1_socket_s *sk_sec = sock_security(sock->sk);

	if (unlikely(!sock_kobj || !sk_sec)) {
		med_pr_err("ERROR: NULL pointer: %s: sock_kobj=%p or sock_security=%p",
			   __func__, sock_kobj, sk_sec);
		return -EINVAL;
	}

	sk_sec->med_object = sock_kobj->med_object;
	med_magic_validate(&sk_sec->med_object);
	return 0;
}

inline int socket_kern2kobj(struct socket_kobject *sock_kobj, struct socket *sock)
{
	struct inode *inode = SOCK_INODE(sock);
	struct medusa_l1_socket_s *sk_sec = sock_security(sock->sk);

	if (unlikely(!sock_kobj || !sk_sec || !inode)) {
		med_pr_err("ERROR: NULL pointer: %s: sock_kobj=%p or sock_security=%p or sock_inode=%p",
			   __func__, sock_kobj, sk_sec, inode);
		return -EINVAL;
	}

	sock_kobj->dev = inode->i_sb->s_dev;
	sock_kobj->ino = inode->i_ino;

	sock_kobj->type = sock->type;
	sock_kobj->family = sock->sk->sk_family;
	sock_kobj->protocol = sock->sk->sk_protocol;
	sock_kobj->netns_cookie = sock_net(sock->sk)->net_cookie;
	sock_kobj->uid = sock->sk->sk_uid;
	sock_kobj->med_object = sk_sec->med_object;
	return 0;
}

MED_KCLASS(socket_kobject) {
	MEDUSA_KCLASS_HEADER(socket_kobject),
	"socket",
	NULL,		/* init kclass */
	NULL,		/* destroy kclass */
	NULL,		/* fetch: socket inode identity is not lifetime-safe */
	NULL,		/* update: socket state is event-scoped */
	NULL,		/* unmonitor */
};

static int __init socket_kobject_init(void)
{
	MED_REGISTER_KCLASS(socket_kobject);
	return 0;
}

device_initcall(socket_kobject_init);

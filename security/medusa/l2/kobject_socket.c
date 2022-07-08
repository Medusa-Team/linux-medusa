// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <net/sock.h>
#include "../../fs/internal.h" /* For user_get_super() */
#include "l3/registry.h"
#include "l2/kobject_socket.h"

MED_ATTRS(socket_kobject) {
	MED_ATTR_KEY_RO(socket_kobject, dev, "dev", MED_UNSIGNED),
	MED_ATTR_KEY_RO(socket_kobject, ino, "ino", MED_UNSIGNED),

	MED_ATTR_RO(socket_kobject, type, "type", MED_UNSIGNED),
	MED_ATTR_RO(socket_kobject, family, "family", MED_UNSIGNED),
	MED_ATTR_RO(socket_kobject, addrlen, "addrlen", MED_UNSIGNED),
	MED_ATTR(socket_kobject, address, "address", MED_BYTES),
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
	sock_kobj->family = sock->ops->family;
	sock_kobj->uid = sock->sk->sk_uid;
	sock_kobj->addrlen = sk_sec->addrlen;
	if (sk_sec->addrlen > 0) {
		switch (sock->ops->family) {
		case AF_INET:
			sock_kobj->address.inet_i.port = sk_sec->address.inet_i.port;
			memcpy(sock_kobj->address.inet_i.addrdata, sk_sec->address.inet_i.addrdata, 4);
			break;
		case AF_INET6:
			sock_kobj->address.inet6_i.port = sk_sec->address.inet6_i.port;
			memcpy(sock_kobj->address.inet6_i.addrdata, sk_sec->address.inet6_i.addrdata, 16);
			break;
		case AF_UNIX:
			memcpy(sock_kobj->address.unix_i.addrdata, sk_sec->address.unix_i.addrdata, UNIX_PATH_MAX);
			break;
		default:
			break;
		}
	}
	sock_kobj->med_object = sk_sec->med_object;
	return 0;
}

static struct medusa_kobject_s *socket_fetch(struct medusa_kobject_s *kobj)
{
	struct socket *sock;
	struct inode *inode = NULL;
	struct super_block *sb = NULL;
	struct socket_kobject *s_kobj = (struct socket_kobject *) kobj;
	struct medusa_kobject_s *retval = NULL;

	if (s_kobj)
		sb = user_get_super(s_kobj->dev, false);
	if (sb) {
		inode = ilookup(sb, s_kobj->ino);
		drop_super(sb);
	}

	if (inode) {
		sock = SOCKET_I(inode);
		retval = kobj;
		if (unlikely(socket_kern2kobj(s_kobj, sock) < 0))
			retval = NULL;
		iput(inode);
	}

	return retval;
}

static enum medusa_answer_t socket_update(struct medusa_kobject_s *kobj)
{
	struct socket *sock;
	struct inode *inode = NULL;
	struct super_block *sb = NULL;
	struct socket_kobject *s_kobj = (struct socket_kobject *) kobj;
	enum medusa_answer_t retval = MED_ERR;

	if (s_kobj)
		sb = user_get_super(s_kobj->dev, false);
	if (sb) {
		inode = ilookup(sb, s_kobj->ino);
		drop_super(sb);
	}
	if (inode) {
		sock = SOCKET_I(inode);
		retval = MED_ALLOW;
		if (unlikely(socket_kobj2kern(s_kobj, sock) < 0))
			retval = MED_ERR;
		iput(inode);
	}

	return retval;
}

MED_KCLASS(socket_kobject) {
	MEDUSA_KCLASS_HEADER(socket_kobject),
	"socket",
	NULL,		/* init kclass */
	NULL,		/* destroy kclass */
	socket_fetch,
	socket_update,
	NULL,		/* unmonitor */
};

int __init socket_kobject_init(void)
{
	MED_REGISTER_KCLASS(socket_kobject);
	return 0;
}

device_initcall(socket_kobject_init);

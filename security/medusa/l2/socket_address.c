// SPDX-License-Identifier: GPL-2.0-only

#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/un.h>
#include <net/ipv6.h>

#include "l1/socket.h"

int medusa_socket_address_parse(struct medusa_socket_address *destination,
				const struct sockaddr *address, int addrlen)
{
	size_t unix_offset = offsetof(struct sockaddr_un, sun_path);
	size_t data_length;

	if (!destination || !address || addrlen < sizeof(address->sa_family))
		return -EINVAL;

	memset(destination, 0, sizeof(*destination));
	destination->family = address->sa_family;
	destination->addrlen = addrlen;

	switch (address->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *inet = (const void *)address;

		if (addrlen < sizeof(*inet))
			return -EINVAL;
		destination->data_length = sizeof(destination->value.inet);
		destination->value.inet.port = inet->sin_port;
		destination->value.inet.addr = inet->sin_addr;
		return 0;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *inet6 = (const void *)address;

		if (addrlen < sizeof(*inet6))
			return -EINVAL;
		destination->data_length = sizeof(destination->value.inet6);
		destination->value.inet6.port = inet6->sin6_port;
		destination->value.inet6.flowinfo = inet6->sin6_flowinfo;
		destination->value.inet6.addr = inet6->sin6_addr;
		destination->value.inet6.scope_id = inet6->sin6_scope_id;
		return 0;
	}
	case AF_UNIX: {
		const struct sockaddr_un *unix_address = (const void *)address;

		if (addrlen < unix_offset)
			return -EINVAL;
		data_length = min_t(size_t, addrlen - unix_offset, UNIX_PATH_MAX);
		destination->data_length = data_length;
		memcpy(destination->value.unix_addr.addrdata,
		       unix_address->sun_path,
		       data_length);
		return 0;
	}
	default:
		return -EAFNOSUPPORT;
	}
}

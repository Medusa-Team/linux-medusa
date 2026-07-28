/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _MEDUSA_TRANSPORT_H
#define _MEDUSA_TRANSPORT_H

/*
 * Protocol engines submit complete frames through this ownership-transfer
 * boundary.  A future transport (for example Generic Netlink) can provide a
 * different queue implementation without changing decision handling.
 */
struct medusa_transport {
	const char *name;
	void *context;
	int (*queue)(void *context, void *frame);
};

static inline int medusa_transport_queue(struct medusa_transport *transport,
					 void *frame)
{
	return transport->queue(transport->context, frame);
}

#endif /* _MEDUSA_TRANSPORT_H */

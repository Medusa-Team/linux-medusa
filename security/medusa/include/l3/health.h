/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _MEDUSA_HEALTH_H
#define _MEDUSA_HEALTH_H

#include <linux/atomic.h>
#include <linux/types.h>

enum medusa_health_reason {
	MEDUSA_HEALTHY,
	MEDUSA_HEALTH_DISCONNECTED,
	MEDUSA_HEALTH_DECISION_TIMEOUT,
	MEDUSA_HEALTH_OVERLOADED,
	MEDUSA_HEALTH_PROTOCOL_ERROR,
};

struct medusa_server_health {
	atomic_t healthy;
	atomic_t reason;
};

#define MEDUSA_SERVER_HEALTH_INIT					\
	{								\
		.healthy = ATOMIC_INIT(0),				\
		.reason = ATOMIC_INIT(MEDUSA_HEALTH_DISCONNECTED),	\
	}

void medusa_server_health_mark_healthy(struct medusa_server_health *health);
bool medusa_server_health_mark_unhealthy(struct medusa_server_health *health,
					 enum medusa_health_reason reason);
bool medusa_server_health_is_healthy(const struct medusa_server_health *health);
enum medusa_health_reason
medusa_server_health_reason(const struct medusa_server_health *health);
const char *medusa_health_reason_name(enum medusa_health_reason reason);

#endif /* _MEDUSA_HEALTH_H */

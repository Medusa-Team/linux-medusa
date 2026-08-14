// SPDX-License-Identifier: GPL-2.0-only

#include "l3/health.h"

void medusa_server_health_mark_healthy(struct medusa_server_health *health)
{
	atomic_set(&health->reason, MEDUSA_HEALTHY);
	atomic_set(&health->healthy, 1);
}

bool medusa_server_health_mark_unhealthy(struct medusa_server_health *health,
					 enum medusa_health_reason reason)
{
	atomic_set(&health->reason, reason);
	return atomic_xchg(&health->healthy, 0);
}

bool medusa_server_health_is_healthy(const struct medusa_server_health *health)
{
	return atomic_read(&health->healthy);
}

enum medusa_health_reason
medusa_server_health_reason(const struct medusa_server_health *health)
{
	return atomic_read(&health->reason);
}

const char *medusa_health_reason_name(enum medusa_health_reason reason)
{
	switch (reason) {
	case MEDUSA_HEALTHY:
		return "healthy";
	case MEDUSA_HEALTH_DISCONNECTED:
		return "disconnected";
	case MEDUSA_HEALTH_DECISION_TIMEOUT:
		return "decision_timeout";
	case MEDUSA_HEALTH_OVERLOADED:
		return "overloaded";
	case MEDUSA_HEALTH_PROTOCOL_ERROR:
		return "protocol_error";
	default:
		return "invalid";
	}
}

// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>

#include "l3/protocol_stats.h"

static atomic64_t protocol_replies = ATOMIC64_INIT(0);
static atomic64_t protocol_lease_renewals = ATOMIC64_INIT(0);
static atomic64_t protocol_malformed_messages = ATOMIC64_INIT(0);
static atomic64_t protocol_invalid_answers = ATOMIC64_INIT(0);
static atomic64_t protocol_unknown_commands = ATOMIC64_INIT(0);
static atomic64_t protocol_unknown_requests = ATOMIC64_INIT(0);
static atomic64_t protocol_stale_requests = ATOMIC64_INIT(0);

void medusa_protocol_counter_inc(enum medusa_protocol_counter counter)
{
	switch (counter) {
	case MEDUSA_PROTOCOL_REPLIES:
		atomic64_inc(&protocol_replies);
		break;
	case MEDUSA_PROTOCOL_LEASE_RENEWALS:
		atomic64_inc(&protocol_lease_renewals);
		break;
	case MEDUSA_PROTOCOL_MALFORMED_MESSAGES:
		atomic64_inc(&protocol_malformed_messages);
		break;
	case MEDUSA_PROTOCOL_INVALID_ANSWERS:
		atomic64_inc(&protocol_invalid_answers);
		break;
	case MEDUSA_PROTOCOL_UNKNOWN_COMMANDS:
		atomic64_inc(&protocol_unknown_commands);
		break;
	case MEDUSA_PROTOCOL_UNKNOWN_REQUESTS:
		atomic64_inc(&protocol_unknown_requests);
		break;
	case MEDUSA_PROTOCOL_STALE_REQUESTS:
		atomic64_inc(&protocol_stale_requests);
		break;
	}
}

void medusa_protocol_counters_snapshot(
	struct medusa_protocol_counter_snapshot *snapshot)
{
	snapshot->replies = atomic64_read(&protocol_replies);
	snapshot->lease_renewals = atomic64_read(&protocol_lease_renewals);
	snapshot->malformed_messages =
		atomic64_read(&protocol_malformed_messages);
	snapshot->invalid_answers = atomic64_read(&protocol_invalid_answers);
	snapshot->unknown_commands = atomic64_read(&protocol_unknown_commands);
	snapshot->unknown_requests = atomic64_read(&protocol_unknown_requests);
	snapshot->stale_requests = atomic64_read(&protocol_stale_requests);
}

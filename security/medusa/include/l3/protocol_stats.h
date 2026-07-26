/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _MEDUSA_PROTOCOL_STATS_H
#define _MEDUSA_PROTOCOL_STATS_H

#include <linux/types.h>

enum medusa_protocol_counter {
	MEDUSA_PROTOCOL_REPLIES,
	MEDUSA_PROTOCOL_LEASE_RENEWALS,
	MEDUSA_PROTOCOL_MALFORMED_MESSAGES,
	MEDUSA_PROTOCOL_INVALID_ANSWERS,
	MEDUSA_PROTOCOL_UNKNOWN_COMMANDS,
	MEDUSA_PROTOCOL_UNKNOWN_REQUESTS,
	MEDUSA_PROTOCOL_STALE_REQUESTS,
};

struct medusa_protocol_counter_snapshot {
	u64 replies;
	u64 lease_renewals;
	u64 malformed_messages;
	u64 invalid_answers;
	u64 unknown_commands;
	u64 unknown_requests;
	u64 stale_requests;
};

struct medusa_protocol_error_context {
	enum medusa_protocol_counter counter;
	u64 policy_generation;
	u64 command;
	u64 request_id;
	int error;
	bool command_present;
	bool request_present;
};

void medusa_protocol_counter_inc(enum medusa_protocol_counter counter);
void medusa_protocol_counters_snapshot(
	struct medusa_protocol_counter_snapshot *snapshot);
const char *medusa_protocol_error_name(enum medusa_protocol_counter counter);
void medusa_protocol_record_error(const struct medusa_protocol_error_context *context);

#endif /* _MEDUSA_PROTOCOL_STATS_H */

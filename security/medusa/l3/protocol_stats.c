// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/audit.h>
#include <linux/ratelimit.h>

#include "l3/protocol_stats.h"
#include "l4/comm.h"

#define MEDUSA_PROTOCOL_AUDIT_INTERVAL (5 * HZ)
#define MEDUSA_PROTOCOL_AUDIT_BURST 3

static atomic64_t protocol_replies = ATOMIC64_INIT(0);
static atomic64_t protocol_lease_renewals = ATOMIC64_INIT(0);
static atomic64_t protocol_malformed_messages = ATOMIC64_INIT(0);
static atomic64_t protocol_invalid_answers = ATOMIC64_INIT(0);
static atomic64_t protocol_unknown_commands = ATOMIC64_INIT(0);
static atomic64_t protocol_unknown_requests = ATOMIC64_INIT(0);
static atomic64_t protocol_stale_requests = ATOMIC64_INIT(0);

#define MEDUSA_PROTOCOL_RATELIMIT_INIT(name)				\
	RATELIMIT_STATE_INIT_FLAGS(name, MEDUSA_PROTOCOL_AUDIT_INTERVAL,	\
		MEDUSA_PROTOCOL_AUDIT_BURST, RATELIMIT_MSG_ON_RELEASE)

static struct ratelimit_state malformed_message_audit_ratelimit =
	MEDUSA_PROTOCOL_RATELIMIT_INIT(malformed_message_audit_ratelimit);
static struct ratelimit_state invalid_answer_audit_ratelimit =
	MEDUSA_PROTOCOL_RATELIMIT_INIT(invalid_answer_audit_ratelimit);
static struct ratelimit_state unknown_command_audit_ratelimit =
	MEDUSA_PROTOCOL_RATELIMIT_INIT(unknown_command_audit_ratelimit);
static struct ratelimit_state unknown_request_audit_ratelimit =
	MEDUSA_PROTOCOL_RATELIMIT_INIT(unknown_request_audit_ratelimit);
static struct ratelimit_state stale_request_audit_ratelimit =
	MEDUSA_PROTOCOL_RATELIMIT_INIT(stale_request_audit_ratelimit);

static atomic64_t *medusa_protocol_counter(enum medusa_protocol_counter counter)
{
	switch (counter) {
	case MEDUSA_PROTOCOL_REPLIES:
		return &protocol_replies;
	case MEDUSA_PROTOCOL_LEASE_RENEWALS:
		return &protocol_lease_renewals;
	case MEDUSA_PROTOCOL_MALFORMED_MESSAGES:
		return &protocol_malformed_messages;
	case MEDUSA_PROTOCOL_INVALID_ANSWERS:
		return &protocol_invalid_answers;
	case MEDUSA_PROTOCOL_UNKNOWN_COMMANDS:
		return &protocol_unknown_commands;
	case MEDUSA_PROTOCOL_UNKNOWN_REQUESTS:
		return &protocol_unknown_requests;
	case MEDUSA_PROTOCOL_STALE_REQUESTS:
		return &protocol_stale_requests;
	}

	return NULL;
}

static struct ratelimit_state *medusa_protocol_ratelimit(enum medusa_protocol_counter counter)
{
	switch (counter) {
	case MEDUSA_PROTOCOL_MALFORMED_MESSAGES:
		return &malformed_message_audit_ratelimit;
	case MEDUSA_PROTOCOL_INVALID_ANSWERS:
		return &invalid_answer_audit_ratelimit;
	case MEDUSA_PROTOCOL_UNKNOWN_COMMANDS:
		return &unknown_command_audit_ratelimit;
	case MEDUSA_PROTOCOL_UNKNOWN_REQUESTS:
		return &unknown_request_audit_ratelimit;
	case MEDUSA_PROTOCOL_STALE_REQUESTS:
		return &stale_request_audit_ratelimit;
	default:
		return NULL;
	}
}

void medusa_protocol_counter_inc(enum medusa_protocol_counter counter)
{
	atomic64_t *value = medusa_protocol_counter(counter);

	if (value)
		atomic64_inc(value);
}

const char *medusa_protocol_error_name(enum medusa_protocol_counter counter)
{
	switch (counter) {
	case MEDUSA_PROTOCOL_MALFORMED_MESSAGES:
		return "malformed_message";
	case MEDUSA_PROTOCOL_INVALID_ANSWERS:
		return "invalid_answer";
	case MEDUSA_PROTOCOL_UNKNOWN_COMMANDS:
		return "unknown_command";
	case MEDUSA_PROTOCOL_UNKNOWN_REQUESTS:
		return "unknown_request";
	case MEDUSA_PROTOCOL_STALE_REQUESTS:
		return "stale_request";
	default:
		return "invalid";
	}
}

void medusa_protocol_record_error(const struct medusa_protocol_error_context *context)
{
	struct ratelimit_state *ratelimit;
	struct audit_buffer *ab;
	atomic64_t *counter;
	u64 sequence;
	int suppressed;

	if (!context)
		return;

	counter = medusa_protocol_counter(context->counter);
	ratelimit = medusa_protocol_ratelimit(context->counter);
	if (!counter || !ratelimit)
		return;

	sequence = atomic64_inc_return(counter);
	if (!__ratelimit(ratelimit))
		return;

	ab = audit_log_start(audit_context(), GFP_ATOMIC | __GFP_NOWARN,
			     AUDIT_AVC);
	if (!ab)
		return;
	suppressed = ratelimit_state_reset_miss(ratelimit);

	audit_log_format(ab, "Medusa: op=protocol_error protocol=%llu",
			 (unsigned long long)MEDUSA_COMM_VERSION);
	audit_log_format(ab, " policy_generation=%llu error_kind=%s",
			 (unsigned long long)context->policy_generation,
			 medusa_protocol_error_name(context->counter));
	audit_log_format(ab, " command_present=%u command=0x%llx",
			 context->command_present,
			 (unsigned long long)context->command);
	audit_log_format(ab, " request_present=%u request_id=%llu error=%d",
			 context->request_present,
			 (unsigned long long)context->request_id,
			 context->error);
	audit_log_format(ab, " error_sequence=%llu suppressed=%d",
			 (unsigned long long)sequence, suppressed);
	audit_log_end(ab);
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

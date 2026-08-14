/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _MEDUSA_DECISION_H
#define _MEDUSA_DECISION_H

#include <linux/atomic.h>

#include "l3/constants.h"

struct medusa_event_s;
struct medusa_evtype_s;

/*
 * The policy is intentionally a single value so one event's fallback can be
 * replaced atomically while decisions are running.
 */
enum medusa_fallback_policy {
	MEDUSA_FALLBACK_BASELINE_ALLOW,
	MEDUSA_FALLBACK_BASELINE_DENY,
	MEDUSA_FALLBACK_ONLINE_REQUIRED,
};

enum medusa_decision_source {
	MEDUSA_DECISION_AUTH_SERVER,
	MEDUSA_DECISION_BASELINE,
	MEDUSA_DECISION_ONLINE_REQUIRED,
	MEDUSA_DECISION_INVALID_REPLY,
	MEDUSA_DECISION_CACHE,
	MEDUSA_DECISION_VIRTUAL_SPACE,
	MEDUSA_DECISION_PATH_GUARD,
	MEDUSA_DECISION_VALIDATION,
};

enum medusa_unavailable_reason {
	MEDUSA_AVAILABLE,
	MEDUSA_NO_AUTH_SERVER,
	MEDUSA_AUTH_SERVER_UNREACHABLE,
	MEDUSA_AUTH_SERVER_UNHEALTHY,
	MEDUSA_DECISION_TIMED_OUT,
	MEDUSA_AUTH_SERVER_OVERLOADED,
	MEDUSA_NON_SLEEPABLE_CONTEXT,
};

struct medusa_authserver_decision {
	u64 request_id;
	u64 policy_generation;
	enum medusa_unavailable_reason unavailable;
	bool request_present;
	bool contacted;
};

struct medusa_decision_result {
	enum medusa_answer_t answer;
	enum medusa_decision_source source;
	enum medusa_unavailable_reason unavailable;
	u64 request_id;
	u64 policy_generation;
	bool request_present;
	bool authserver_contacted;
};

struct medusa_decision_counters {
	atomic64_t evaluations;
	atomic64_t cached;
	atomic64_t total;
	atomic64_t delegated;
	atomic64_t auth_server;
	atomic64_t baseline;
	atomic64_t online_required;
	atomic64_t allowed;
	atomic64_t denied;
	atomic64_t timed_out;
	atomic64_t invalid_replies;
};

struct medusa_decision_counter_snapshot {
	u64 evaluations;
	u64 cached;
	u64 total;
	u64 delegated;
	u64 auth_server;
	u64 baseline;
	u64 online_required;
	u64 allowed;
	u64 denied;
	u64 timed_out;
	u64 invalid_replies;
};

int medusa_set_fallback_policy(struct medusa_evtype_s *evtype,
			       enum medusa_fallback_policy policy);
enum medusa_fallback_policy
medusa_get_fallback_policy(const struct medusa_evtype_s *evtype);
u64 medusa_degraded_decision_count(const struct medusa_evtype_s *evtype);
void medusa_decision_counters_init(struct medusa_evtype_s *evtype);
void medusa_decision_counters_snapshot(const struct medusa_evtype_s *evtype,
				       struct medusa_decision_counter_snapshot *snapshot);
bool medusa_event_monitoring_check(struct medusa_evtype_s *evtype,
				   bool monitored);
bool medusa_event_fallback_requires_decision(
	const struct medusa_evtype_s *evtype);
u64 medusa_current_policy_generation(void);
const char *medusa_fallback_policy_name(enum medusa_fallback_policy policy);
const char *medusa_decision_answer_name(enum medusa_answer_t answer);
const char *medusa_decision_source_name(enum medusa_decision_source source);
const char *medusa_unavailable_reason_name(
	enum medusa_unavailable_reason reason);
bool medusa_decision_is_authoritative(
	const struct medusa_decision_result *result);
struct medusa_decision_result
med_decide_result(struct medusa_evtype_s *evtype, void *event,
		  void *o1, void *o2);
enum medusa_answer_t med_decide(struct medusa_evtype_s *evtype, void *event,
				void *o1, void *o2);

#endif /* _MEDUSA_DECISION_H */

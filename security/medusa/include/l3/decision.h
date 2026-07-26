/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _MEDUSA_DECISION_H
#define _MEDUSA_DECISION_H

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
};

enum medusa_unavailable_reason {
	MEDUSA_AVAILABLE,
	MEDUSA_NO_AUTH_SERVER,
	MEDUSA_AUTH_SERVER_UNREACHABLE,
};

struct medusa_decision_result {
	enum medusa_answer_t answer;
	enum medusa_decision_source source;
	enum medusa_unavailable_reason unavailable;
	bool authserver_contacted;
};

int medusa_set_fallback_policy(struct medusa_evtype_s *evtype,
			       enum medusa_fallback_policy policy);
struct medusa_decision_result
med_decide_result(struct medusa_evtype_s *evtype, void *event,
		  void *o1, void *o2);
enum medusa_answer_t med_decide(struct medusa_evtype_s *evtype, void *event,
				void *o1, void *o2);

#endif /* _MEDUSA_DECISION_H */

// SPDX-License-Identifier: GPL-2.0

/* (C) 2002 Milan Pikula <www@terminus.sk> */

#include <linux/audit.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>

#include "l3/audit_schema.h"
#include "l3/arch.h"
#include "l3/registry.h"
#include "l3/server.h"

extern struct mutex registry_lock;

inline int is_authserver_reached(enum medusa_answer_t answer)
{
	return (answer != MED_ERR);
}

inline int is_supported_medusa_answer(enum medusa_answer_t answer)
{
	return (answer == MED_ALLOW || answer == MED_DENY);
}

static struct medusa_decision_result
medusa_fallback_result(struct medusa_evtype_s *evtype,
		       enum medusa_fallback_policy policy,
		       enum medusa_unavailable_reason unavailable,
		       u64 request_id, u64 policy_generation,
		       bool request_present, bool authserver_contacted)
{
	struct medusa_decision_result result = {
		.answer = MED_ALLOW,
		.source = MEDUSA_DECISION_BASELINE,
		.unavailable = unavailable,
		.request_id = request_id,
		.policy_generation = policy_generation,
		.request_present = request_present,
		.authserver_contacted = authserver_contacted,
	};

	switch (policy) {
	case MEDUSA_FALLBACK_BASELINE_ALLOW:
		break;
	case MEDUSA_FALLBACK_BASELINE_DENY:
		result.answer = MED_DENY;
		break;
	case MEDUSA_FALLBACK_ONLINE_REQUIRED:
		result.answer = MED_DENY;
		result.source = MEDUSA_DECISION_ONLINE_REQUIRED;
		break;
	default:
		/*
		 * A corrupted policy must not become an allow. Setter validation
		 * prevents this during normal operation.
		 */
		result.answer = MED_DENY;
		result.source = MEDUSA_DECISION_INVALID_REPLY;
		break;
	}
	return result;
}

const char *medusa_decision_answer_name(enum medusa_answer_t answer)
{
	switch (answer) {
	case MED_ERR:
		return "ERROR";
	case MED_DENY:
		return "DENY";
	case MED_ALLOW:
		return "ALLOW";
	default:
		return "INVALID";
	}
}

const char *medusa_decision_source_name(enum medusa_decision_source source)
{
	switch (source) {
	case MEDUSA_DECISION_AUTH_SERVER:
		return "auth_server";
	case MEDUSA_DECISION_BASELINE:
		return "baseline";
	case MEDUSA_DECISION_ONLINE_REQUIRED:
		return "online_required";
	case MEDUSA_DECISION_INVALID_REPLY:
		return "invalid_reply";
	case MEDUSA_DECISION_CACHE:
		return "cache";
	case MEDUSA_DECISION_VIRTUAL_SPACE:
		return "virtual_space";
	case MEDUSA_DECISION_PATH_GUARD:
		return "path_guard";
	case MEDUSA_DECISION_VALIDATION:
		return "validation";
	default:
		return "invalid";
	}
}

const char *medusa_unavailable_reason_name(
	enum medusa_unavailable_reason reason)
{
	switch (reason) {
	case MEDUSA_AVAILABLE:
		return "none";
	case MEDUSA_NO_AUTH_SERVER:
		return "no_auth_server";
	case MEDUSA_AUTH_SERVER_UNREACHABLE:
		return "auth_server_unreachable";
	case MEDUSA_AUTH_SERVER_UNHEALTHY:
		return "auth_server_unhealthy";
	case MEDUSA_DECISION_TIMED_OUT:
		return "decision_timed_out";
	case MEDUSA_AUTH_SERVER_OVERLOADED:
		return "auth_server_overloaded";
	case MEDUSA_NON_SLEEPABLE_CONTEXT:
		return "non_sleepable_context";
	default:
		return "invalid";
	}
}

u64 medusa_degraded_decision_count(const struct medusa_evtype_s *evtype)
{
	if (!evtype)
		return 0;
	return atomic64_read(&evtype->degraded_decisions);
}

void medusa_decision_counters_init(struct medusa_evtype_s *evtype)
{
	atomic64_set(&evtype->decision_counters.evaluations, 0);
	atomic64_set(&evtype->decision_counters.cached, 0);
	atomic64_set(&evtype->decision_counters.total, 0);
	atomic64_set(&evtype->decision_counters.delegated, 0);
	atomic64_set(&evtype->decision_counters.auth_server, 0);
	atomic64_set(&evtype->decision_counters.baseline, 0);
	atomic64_set(&evtype->decision_counters.online_required, 0);
	atomic64_set(&evtype->decision_counters.allowed, 0);
	atomic64_set(&evtype->decision_counters.denied, 0);
	atomic64_set(&evtype->decision_counters.timed_out, 0);
	atomic64_set(&evtype->decision_counters.invalid_replies, 0);
}

void medusa_decision_counters_snapshot(const struct medusa_evtype_s *evtype,
				       struct medusa_decision_counter_snapshot *snapshot)
{
	snapshot->evaluations =
		atomic64_read(&evtype->decision_counters.evaluations);
	snapshot->cached =
		atomic64_read(&evtype->decision_counters.cached);
	snapshot->total = atomic64_read(&evtype->decision_counters.total);
	snapshot->delegated =
		atomic64_read(&evtype->decision_counters.delegated);
	snapshot->auth_server =
		atomic64_read(&evtype->decision_counters.auth_server);
	snapshot->baseline =
		atomic64_read(&evtype->decision_counters.baseline);
	snapshot->online_required =
		atomic64_read(&evtype->decision_counters.online_required);
	snapshot->allowed =
		atomic64_read(&evtype->decision_counters.allowed);
	snapshot->denied = atomic64_read(&evtype->decision_counters.denied);
	snapshot->timed_out =
		atomic64_read(&evtype->decision_counters.timed_out);
	snapshot->invalid_replies =
		atomic64_read(&evtype->decision_counters.invalid_replies);
}

bool medusa_event_monitoring_check(struct medusa_evtype_s *evtype,
				   bool monitored)
{
	if (medusa_event_fallback_requires_decision(evtype))
		monitored = true;

	atomic64_inc(&evtype->decision_counters.evaluations);
	if (!monitored) {
		atomic64_inc(&evtype->decision_counters.cached);
		atomic64_inc(&evtype->decision_counters.total);
		atomic64_inc(&evtype->decision_counters.allowed);
	}
	return monitored;
}

bool medusa_event_fallback_requires_decision(
	const struct medusa_evtype_s *evtype)
{
	return medusa_get_fallback_policy(evtype) !=
	       MEDUSA_FALLBACK_BASELINE_ALLOW;
}

u64 medusa_current_policy_generation(void)
{
	return (u64)READ_ONCE(medusa_authserver_magic);
}

const char *medusa_fallback_policy_name(enum medusa_fallback_policy policy)
{
	switch (policy) {
	case MEDUSA_FALLBACK_BASELINE_ALLOW:
		return "baseline_allow";
	case MEDUSA_FALLBACK_BASELINE_DENY:
		return "baseline_deny";
	case MEDUSA_FALLBACK_ONLINE_REQUIRED:
		return "online_required";
	default:
		return "invalid";
	}
}

static void medusa_audit_degraded_decision(
	struct medusa_evtype_s *evtype,
	const struct medusa_decision_result *result)
{
	struct audit_buffer *ab;
	int suppressed;
	u64 sequence;

	if (result->unavailable == MEDUSA_AVAILABLE)
		return;

	sequence = atomic64_inc_return(&evtype->degraded_decisions);
	if (!__ratelimit(&evtype->degraded_audit_ratelimit))
		return;

	ab = audit_log_start(audit_context(), GFP_ATOMIC | __GFP_NOWARN,
			     AUDIT_AVC);
	if (!ab)
		return;
	suppressed =
		ratelimit_state_reset_miss(&evtype->degraded_audit_ratelimit);

	audit_log_format(
		ab,
		"Medusa: audit_schema=%u record=%s protocol=%llu"
		" policy_generation=%llu event_id=%s event_bit=%u"
		" subject_class_id=%s object_class_id=%s"
		" request_present=%u request_id=%llu verdict=%s"
		" verdict_source=%s unavailable=%s"
		" authserver_contacted=%u"
		" degraded_sequence=%llu suppressed=%d",
		MEDUSA_AUDIT_SCHEMA_VERSION, MEDUSA_AUDIT_RECORD_DECISION,
		(unsigned long long)MEDUSA_PROTOCOL_VERSION,
		(unsigned long long)result->policy_generation,
		evtype->name, evtype->bitnr & MASK_BITNR,
		evtype->arg_kclass[0]->name, evtype->arg_kclass[1]->name,
		result->request_present,
		(unsigned long long)result->request_id,
		medusa_decision_answer_name(result->answer),
		medusa_decision_source_name(result->source),
		medusa_unavailable_reason_name(result->unavailable),
		result->authserver_contacted,
		(unsigned long long)sequence, suppressed);
	audit_log_end(ab);
}

static void
medusa_account_decision(struct medusa_evtype_s *evtype,
			const struct medusa_decision_result *result)
{
	atomic64_inc(&evtype->decision_counters.total);
	if (result->authserver_contacted)
		atomic64_inc(&evtype->decision_counters.delegated);

	switch (result->source) {
	case MEDUSA_DECISION_CACHE:
		atomic64_inc(&evtype->decision_counters.cached);
		break;
	case MEDUSA_DECISION_AUTH_SERVER:
		atomic64_inc(&evtype->decision_counters.auth_server);
		break;
	case MEDUSA_DECISION_BASELINE:
		atomic64_inc(&evtype->decision_counters.baseline);
		break;
	case MEDUSA_DECISION_ONLINE_REQUIRED:
		atomic64_inc(&evtype->decision_counters.online_required);
		break;
	case MEDUSA_DECISION_INVALID_REPLY:
		atomic64_inc(&evtype->decision_counters.invalid_replies);
		break;
	default:
		break;
	}

	if (result->answer == MED_ALLOW)
		atomic64_inc(&evtype->decision_counters.allowed);
	else if (result->answer == MED_DENY)
		atomic64_inc(&evtype->decision_counters.denied);

	if (result->unavailable == MEDUSA_DECISION_TIMED_OUT)
		atomic64_inc(&evtype->decision_counters.timed_out);
}

static struct medusa_decision_result
medusa_finish_decision(struct medusa_evtype_s *evtype,
		       struct medusa_decision_result result)
{
	medusa_account_decision(evtype, &result);
	medusa_audit_degraded_decision(evtype, &result);
	return result;
}

int medusa_set_fallback_policy(struct medusa_evtype_s *evtype,
			       enum medusa_fallback_policy policy)
{
	if (!evtype)
		return -EINVAL;
	if (policy < MEDUSA_FALLBACK_BASELINE_ALLOW ||
	    policy > MEDUSA_FALLBACK_ONLINE_REQUIRED)
		return -EINVAL;

	WRITE_ONCE(evtype->fallback_policy[0], policy);
	WRITE_ONCE(evtype->fallback_policy[1], policy);
	return 0;
}

bool medusa_decision_is_authoritative(
	const struct medusa_decision_result *result)
{
	return result &&
	       result->source == MEDUSA_DECISION_AUTH_SERVER &&
	       result->unavailable == MEDUSA_AVAILABLE &&
	       result->request_present &&
	       result->authserver_contacted &&
	       is_supported_medusa_answer(result->answer);
}

struct medusa_decision_result
med_decide_result(struct medusa_evtype_s *evtype, void *event,
		  void *o1, void *o2)
{
	struct medusa_decision_result result;
	struct medusa_authserver_decision server_decision = {
		.unavailable = MEDUSA_AUTH_SERVER_UNREACHABLE,
	};
	struct medusa_authserver_s *authserver;
	enum medusa_fallback_policy fallback_policy =
		medusa_get_fallback_policy(evtype);
	u64 policy_generation =
		(u64)READ_ONCE(medusa_authserver_magic);

	if (ARCH_CANNOT_DECIDE(evtype)) {
		result = medusa_fallback_result(evtype, fallback_policy,
						MEDUSA_NON_SLEEPABLE_CONTEXT,
						0, policy_generation, false,
						false);
		return medusa_finish_decision(evtype, result);
	}

	mutex_lock(&registry_lock);
#ifdef CONFIG_MEDUSA_PROFILING
	evtype->arg_kclass[0]->l2_to_l4++;
	evtype->arg_kclass[1]->l2_to_l4++;
	evtype->l2_to_l4++;
#endif
	authserver = med_get_authserver();
	if (!authserver) {
		enum medusa_unavailable_reason unavailable =
			fallback_policy == MEDUSA_FALLBACK_BASELINE_DENY ?
				MEDUSA_AVAILABLE : MEDUSA_NO_AUTH_SERVER;

		mutex_unlock(&registry_lock);
		result = medusa_fallback_result(evtype, fallback_policy,
						unavailable,
						0, policy_generation, false,
						false);
		return medusa_finish_decision(evtype, result);
	}
	mutex_unlock(&registry_lock);

	/*
	 * Never address an authorization request to the task that must answer
	 * it.  This also lets Constable create its worker pool immediately after
	 * READY invalidates the task generation.
	 */
	if (task_tgid(current) == authserver->tgid) {
		med_put_authserver(authserver);
		result = (struct medusa_decision_result) {
			.answer = MED_ALLOW,
			.source = MEDUSA_DECISION_CACHE,
			.unavailable = MEDUSA_AVAILABLE,
			.policy_generation = policy_generation,
		};
		return medusa_finish_decision(evtype, result);
	}

	/*
	 * An installed denial is authoritative and is never weakened by the
	 * availability or answer of a userspace server.
	 */
	if (fallback_policy == MEDUSA_FALLBACK_BASELINE_DENY) {
		med_put_authserver(authserver);
		result = medusa_fallback_result(evtype, fallback_policy,
						MEDUSA_AVAILABLE,
						0, policy_generation, false,
						false);
		return medusa_finish_decision(evtype, result);
	}

	if (authserver->is_healthy && !authserver->is_healthy()) {
		med_pr_warn_ratelimited("authorization server unhealthy, using fallback for event '%s'\n",
				       evtype->name);
		med_put_authserver(authserver);
		result = medusa_fallback_result(evtype, fallback_policy,
						MEDUSA_AUTH_SERVER_UNHEALTHY,
						0, policy_generation, false,
						false);
		return medusa_finish_decision(evtype, result);
	}

	((struct medusa_event_s *)event)->evtype_id = evtype;
	server_decision.policy_generation = policy_generation;
	result.answer = authserver->decide(event, o1, o2, &server_decision);
	result.source = MEDUSA_DECISION_AUTH_SERVER;
	result.unavailable = MEDUSA_AVAILABLE;
	result.request_id = server_decision.request_id;
	result.policy_generation = server_decision.policy_generation;
	result.request_present = server_decision.request_present;
	result.authserver_contacted = server_decision.contacted;
	if (!is_authserver_reached(result.answer)) {
		result = medusa_fallback_result(evtype, fallback_policy,
					       server_decision.unavailable,
					       server_decision.request_id,
					       server_decision.policy_generation,
					       server_decision.request_present,
					       server_decision.contacted);
	} else if (!is_supported_medusa_answer(result.answer)) {
		char *err_str = "ERROR: authserver returned not supported answer";

		/* if we received code which is not known or not supported, we
		 * want to DENY the operation since according to protocol, the
		 * authorization server should send Medusa only supported codes
		 * and if it did not, this is suspicious
		 */
		med_pr_err("%s %d for event %s(%s:%s->%s:%s)\n",
			   err_str, result.answer, evtype->name,
			   evtype->arg_name[0], evtype->arg_kclass[0]->name,
			   evtype->arg_name[1], evtype->arg_kclass[1]->name);
		result.answer = MED_DENY;
		result.source = MEDUSA_DECISION_INVALID_REPLY;
	}
#ifdef CONFIG_MEDUSA_PROFILING
	else {
		MED_LOCK_W(registry_lock);
		evtype->l4_to_l2++;
		MED_UNLOCK_W(registry_lock);
	}
#endif
	med_put_authserver(authserver);
	return medusa_finish_decision(evtype, result);
}

enum medusa_answer_t med_decide(struct medusa_evtype_s *evtype, void *event,
				void *o1, void *o2)
{
	return med_decide_result(evtype, event, o1, o2).answer;
}

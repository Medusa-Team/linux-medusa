// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/ratelimit.h>

#include "l3/registry.h"
#include "l3/protocol_stats.h"
#include "l4/protocol.h"

static enum medusa_answer_t delegated_answer;
static int decide_calls;
static int close_calls;
static int subject_unmonitor_calls;
static int object_unmonitor_calls;
static bool server_healthy;
static enum medusa_unavailable_reason delegated_unavailable;

static void fake_close(void)
{
	close_calls++;
}

static enum medusa_answer_t fake_decide(struct medusa_event_s *event,
					struct medusa_kobject_s *subject,
					struct medusa_kobject_s *object,
					struct medusa_authserver_decision *decision)
{
	decision->request_id = 0x1234;
	decision->policy_generation =
		(u64)READ_ONCE(medusa_authserver_magic);
	decision->unavailable = delegated_unavailable;
	decision->request_present = true;
	decision->contacted = true;
	decide_calls++;
	return delegated_answer;
}

static bool fake_is_healthy(void)
{
	return server_healthy;
}

static void fake_subject_unmonitor(struct medusa_kobject_s *object)
{
	subject_unmonitor_calls++;
}

static void fake_object_unmonitor(struct medusa_kobject_s *object)
{
	object_unmonitor_calls++;
}

static struct medusa_kclass_s subject_class = {
	.kobject_size = sizeof(struct medusa_kobject_s),
	.name = "test_subject",
	.unmonitor = fake_subject_unmonitor,
};

static struct medusa_kclass_s object_class = {
	.kobject_size = sizeof(struct medusa_kobject_s),
	.name = "test_object",
	.unmonitor = fake_object_unmonitor,
};

static struct medusa_evtype_s test_event_type = {
	.name = "test_decide",
	.arg_kclass = { &subject_class, &object_class },
	.arg_name = { "subject", "object" },
	.event_size = sizeof(struct medusa_event_s),
};

static struct medusa_authserver_s fake_server = {
	.name = "kunit-comm",
	.close = fake_close,
	.decide = fake_decide,
	.is_healthy = fake_is_healthy,
};

static int comm_test_init(struct kunit *test)
{
	subject_unmonitor_calls = 0;
	object_unmonitor_calls = 0;
	decide_calls = 0;
	delegated_answer = MED_ALLOW;
	server_healthy = true;
	delegated_unavailable = MEDUSA_AUTH_SERVER_UNREACHABLE;
	atomic64_set(&test_event_type.degraded_decisions, 0);
	medusa_decision_counters_init(&test_event_type);
	WRITE_ONCE(test_event_type.enforced, false);
	WRITE_ONCE(test_event_type.delegation_context,
		   MEDUSA_DELEGATION_NONE);
	ratelimit_state_init(&test_event_type.degraded_audit_ratelimit, HZ, 0);
	KUNIT_ASSERT_EQ(test, 0,
			medusa_set_fallback_policy(
				&test_event_type,
				MEDUSA_FALLBACK_BASELINE_ALLOW));
	return 0;
}

static void
decide_without_server_uses_baseline_and_preserves_monitoring(struct kunit *test)
{
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;
	struct medusa_decision_result result;

	result = med_decide_result(&test_event_type, &event, &subject, &object);

	KUNIT_EXPECT_EQ(test, MED_ALLOW, result.answer);
	KUNIT_EXPECT_EQ(test, MEDUSA_DECISION_BASELINE, result.source);
	KUNIT_EXPECT_EQ(test, MEDUSA_NO_AUTH_SERVER, result.unavailable);
	KUNIT_EXPECT_EQ(test, (u64)0, result.request_id);
	KUNIT_EXPECT_EQ(test, (u64)READ_ONCE(medusa_authserver_magic),
			result.policy_generation);
	KUNIT_EXPECT_FALSE(test, result.request_present);
	KUNIT_EXPECT_FALSE(test, result.authserver_contacted);
	KUNIT_EXPECT_EQ(test, (u64)1,
			medusa_degraded_decision_count(&test_event_type));
	KUNIT_EXPECT_EQ(test, 0, subject_unmonitor_calls);
	KUNIT_EXPECT_EQ(test, 0, object_unmonitor_calls);
}

static void baseline_deny_is_enforced_without_server(struct kunit *test)
{
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;
	struct medusa_decision_result result;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_set_fallback_policy(
				&test_event_type,
				MEDUSA_FALLBACK_BASELINE_DENY));
	result = med_decide_result(&test_event_type, &event, &subject, &object);

	KUNIT_EXPECT_EQ(test, MED_DENY, result.answer);
	KUNIT_EXPECT_EQ(test, MEDUSA_DECISION_BASELINE, result.source);
	KUNIT_EXPECT_EQ(test, MEDUSA_AVAILABLE, result.unavailable);
	KUNIT_EXPECT_FALSE(test, result.request_present);
	KUNIT_EXPECT_FALSE(test, result.authserver_contacted);
	KUNIT_EXPECT_EQ(test, (u64)0,
			medusa_degraded_decision_count(&test_event_type));
	KUNIT_EXPECT_EQ(test, 0, decide_calls);
}

static void baseline_deny_cannot_be_overridden_by_server(struct kunit *test)
{
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;
	struct medusa_decision_result result;
	int register_result;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_set_fallback_policy(
				&test_event_type,
				MEDUSA_FALLBACK_BASELINE_DENY));
	delegated_answer = MED_ALLOW;
	register_result = med_register_authserver(&fake_server);
	KUNIT_ASSERT_EQ(test, 0, register_result);

	result = med_decide_result(&test_event_type, &event, &subject, &object);
	med_unregister_authserver(&fake_server);

	KUNIT_EXPECT_EQ(test, MED_DENY, result.answer);
	KUNIT_EXPECT_EQ(test, MEDUSA_DECISION_BASELINE, result.source);
	KUNIT_EXPECT_EQ(test, 0, decide_calls);
}

static void online_required_denies_without_server(struct kunit *test)
{
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;
	struct medusa_decision_result result;
	enum medusa_fallback_policy policy;
	int error;

	policy = MEDUSA_FALLBACK_ONLINE_REQUIRED;
	error = medusa_set_fallback_policy(&test_event_type, policy);
	KUNIT_ASSERT_EQ(test, 0, error);
	result = med_decide_result(&test_event_type, &event, &subject, &object);

	KUNIT_EXPECT_EQ(test, MED_DENY, result.answer);
	KUNIT_EXPECT_EQ(test, MEDUSA_DECISION_ONLINE_REQUIRED, result.source);
	KUNIT_EXPECT_EQ(test, MEDUSA_NO_AUTH_SERVER, result.unavailable);
}

static void expect_delegated_answer(struct kunit *test,
				    enum medusa_answer_t server_answer,
				    enum medusa_answer_t expected,
				    enum medusa_decision_source expected_source,
				    enum medusa_unavailable_reason unavailable)
{
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;
	struct medusa_decision_result decision;
	u64 expected_generation;
	int result;

	delegated_answer = server_answer;
	decide_calls = 0;
	close_calls = 0;
	result = med_register_authserver(&fake_server);
	KUNIT_ASSERT_EQ(test, 0, result);
	expected_generation = (u64)READ_ONCE(medusa_authserver_magic);

	decision = med_decide_result(&test_event_type, &event, &subject,
				     &object);
	med_unregister_authserver(&fake_server);

	KUNIT_EXPECT_EQ(test, expected, decision.answer);
	KUNIT_EXPECT_EQ(test, expected_source, decision.source);
	KUNIT_EXPECT_EQ(test, unavailable, decision.unavailable);
	KUNIT_EXPECT_TRUE(test, decision.authserver_contacted);
	KUNIT_EXPECT_TRUE(test, decision.request_present);
	KUNIT_EXPECT_EQ(test, (u64)0x1234, decision.request_id);
	KUNIT_EXPECT_EQ(test, expected_generation, decision.policy_generation);
	KUNIT_EXPECT_EQ(test,
			unavailable == MEDUSA_AVAILABLE ? (u64)0 : (u64)1,
			medusa_degraded_decision_count(&test_event_type));
	KUNIT_EXPECT_EQ(test, 1, decide_calls);
	KUNIT_EXPECT_PTR_EQ(test, &test_event_type, event.evtype_id);
	KUNIT_EXPECT_EQ(test, 1, close_calls);
}

static void decide_propagates_allow(struct kunit *test)
{
	expect_delegated_answer(test, MED_ALLOW, MED_ALLOW,
				MEDUSA_DECISION_AUTH_SERVER,
				MEDUSA_AVAILABLE);
}

static void decide_propagates_deny(struct kunit *test)
{
	expect_delegated_answer(test, MED_DENY, MED_DENY,
				MEDUSA_DECISION_AUTH_SERVER,
				MEDUSA_AVAILABLE);
}

static void decide_uses_baseline_when_server_is_unreachable(struct kunit *test)
{
	expect_delegated_answer(test, MED_ERR, MED_ALLOW,
				MEDUSA_DECISION_BASELINE,
				MEDUSA_AUTH_SERVER_UNREACHABLE);
}

static void online_required_denies_when_server_is_unreachable(struct kunit *test)
{
	KUNIT_ASSERT_EQ(test, 0,
			medusa_set_fallback_policy(
				&test_event_type,
				MEDUSA_FALLBACK_ONLINE_REQUIRED));
	expect_delegated_answer(test, MED_ERR, MED_DENY,
				MEDUSA_DECISION_ONLINE_REQUIRED,
				MEDUSA_AUTH_SERVER_UNREACHABLE);
}

static void unhealthy_server_uses_baseline_without_contact(struct kunit *test)
{
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;
	struct medusa_decision_result result;
	int register_result;

	server_healthy = false;
	register_result = med_register_authserver(&fake_server);
	KUNIT_ASSERT_EQ(test, 0, register_result);

	result = med_decide_result(&test_event_type, &event, &subject, &object);
	med_unregister_authserver(&fake_server);

	KUNIT_EXPECT_EQ(test, MED_ALLOW, result.answer);
	KUNIT_EXPECT_EQ(test, MEDUSA_DECISION_BASELINE, result.source);
	KUNIT_EXPECT_EQ(test, MEDUSA_AUTH_SERVER_UNHEALTHY,
			result.unavailable);
	KUNIT_EXPECT_FALSE(test, result.request_present);
	KUNIT_EXPECT_FALSE(test, result.authserver_contacted);
	KUNIT_EXPECT_EQ(test, 0, decide_calls);
}

static void decide_denies_unsupported_server_answer(struct kunit *test)
{
	expect_delegated_answer(test, (enum medusa_answer_t)2, MED_DENY,
				MEDUSA_DECISION_INVALID_REPLY,
				MEDUSA_AVAILABLE);
}

static void authoritative_server_results_can_validate(struct kunit *test)
{
	struct medusa_decision_result result = {
		.answer = MED_ALLOW,
		.source = MEDUSA_DECISION_AUTH_SERVER,
		.unavailable = MEDUSA_AVAILABLE,
		.request_present = true,
		.authserver_contacted = true,
	};

	KUNIT_EXPECT_TRUE(test, medusa_decision_is_authoritative(&result));
	result.answer = MED_DENY;
	KUNIT_EXPECT_TRUE(test, medusa_decision_is_authoritative(&result));
}

static void fallback_results_cannot_validate(struct kunit *test)
{
	struct medusa_decision_result result = {
		.answer = MED_ALLOW,
		.source = MEDUSA_DECISION_BASELINE,
		.unavailable = MEDUSA_NO_AUTH_SERVER,
		.authserver_contacted = false,
	};

	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(NULL));
	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));

	result.answer = MED_DENY;
	result.unavailable = MEDUSA_AVAILABLE;
	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));

	result.source = MEDUSA_DECISION_ONLINE_REQUIRED;
	result.unavailable = MEDUSA_AUTH_SERVER_UNREACHABLE;
	result.authserver_contacted = true;
	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));

	result.source = MEDUSA_DECISION_BASELINE;
	result.unavailable = MEDUSA_AUTH_SERVER_UNHEALTHY;
	result.authserver_contacted = false;
	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));
}

static void incomplete_server_results_cannot_validate(struct kunit *test)
{
	struct medusa_decision_result result = {
		.answer = MED_ALLOW,
		.source = MEDUSA_DECISION_AUTH_SERVER,
		.unavailable = MEDUSA_AVAILABLE,
		.authserver_contacted = false,
	};

	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));

	result.authserver_contacted = true;
	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));

	result.request_present = true;
	result.unavailable = MEDUSA_AUTH_SERVER_UNREACHABLE;
	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));

	result.unavailable = MEDUSA_AVAILABLE;
	result.source = MEDUSA_DECISION_INVALID_REPLY;
	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));

	result.source = MEDUSA_DECISION_AUTH_SERVER;
	result.answer = MED_ERR;
	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));

	result.answer = (enum medusa_answer_t)2;
	KUNIT_EXPECT_FALSE(test, medusa_decision_is_authoritative(&result));
}

static void decision_metadata_names_are_stable(struct kunit *test)
{
	const char *source_name;

	KUNIT_EXPECT_STREQ(test, "ALLOW",
			  medusa_decision_answer_name(MED_ALLOW));
	KUNIT_EXPECT_STREQ(test, "DENY",
			  medusa_decision_answer_name(MED_DENY));
	KUNIT_EXPECT_STREQ(test, "decision_timed_out",
			  medusa_unavailable_reason_name(
				  MEDUSA_DECISION_TIMED_OUT));
	KUNIT_EXPECT_STREQ(test, "auth_server_overloaded",
			  medusa_unavailable_reason_name(
				  MEDUSA_AUTH_SERVER_OVERLOADED));
	KUNIT_EXPECT_STREQ(test, "non_sleepable_context",
			  medusa_unavailable_reason_name(
				  MEDUSA_NON_SLEEPABLE_CONTEXT));
	source_name = medusa_decision_source_name(MEDUSA_DECISION_AUTH_SERVER);
	KUNIT_EXPECT_STREQ(test, "auth_server", source_name);
	source_name = medusa_decision_source_name(MEDUSA_DECISION_CACHE);
	KUNIT_EXPECT_STREQ(test, "cache", source_name);
	source_name = medusa_decision_source_name(MEDUSA_DECISION_VIRTUAL_SPACE);
	KUNIT_EXPECT_STREQ(test, "virtual_space", source_name);
	source_name = medusa_decision_source_name(MEDUSA_DECISION_PATH_GUARD);
	KUNIT_EXPECT_STREQ(test, "path_guard", source_name);
	source_name = medusa_decision_source_name(MEDUSA_DECISION_VALIDATION);
	KUNIT_EXPECT_STREQ(test, "validation", source_name);
	KUNIT_EXPECT_EQ(test, (u64)0,
			medusa_degraded_decision_count(NULL));
}

static void fallback_policy_rejects_invalid_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL,
			medusa_set_fallback_policy(NULL,
				MEDUSA_FALLBACK_BASELINE_ALLOW));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			medusa_set_fallback_policy(
				&test_event_type,
				(enum medusa_fallback_policy)-1));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			medusa_set_fallback_policy(
				&test_event_type,
				(enum medusa_fallback_policy)3));
}

static void fallback_policy_names_are_stable(struct kunit *test)
{
	const char *name;

	name = medusa_fallback_policy_name(MEDUSA_FALLBACK_BASELINE_ALLOW);
	KUNIT_EXPECT_STREQ(test, "baseline_allow", name);
	name = medusa_fallback_policy_name(MEDUSA_FALLBACK_BASELINE_DENY);
	KUNIT_EXPECT_STREQ(test, "baseline_deny", name);
	name = medusa_fallback_policy_name(MEDUSA_FALLBACK_ONLINE_REQUIRED);
	KUNIT_EXPECT_STREQ(test, "online_required", name);
	name = medusa_fallback_policy_name((enum medusa_fallback_policy)-1);
	KUNIT_EXPECT_STREQ(test, "invalid", name);
}

static void protocol_accepts_supported_answers(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0, medusa_v4_validate_answer(MED_ALLOW));
	KUNIT_EXPECT_EQ(test, 0, medusa_v4_validate_answer(MED_DENY));
	KUNIT_EXPECT_EQ(test, 0, medusa_v4_validate_answer(MED_ERR));
}

static void protocol_enforces_state_machine(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, medusa_v4_message_allowed(
		MEDUSA_STATE_HANDSHAKE, MEDUSA_MSG_HELLO));
	KUNIT_EXPECT_FALSE(test, medusa_v4_message_allowed(
		MEDUSA_STATE_HANDSHAKE, MEDUSA_MSG_POLICY_BEGIN));
	KUNIT_EXPECT_TRUE(test, medusa_v4_message_allowed(
		MEDUSA_STATE_DEFINITIONS, MEDUSA_MSG_POLICY_BEGIN));
	KUNIT_EXPECT_TRUE(test, medusa_v4_message_allowed(
		MEDUSA_STATE_POLICY_INSTALL, MEDUSA_MSG_POLICY_EVENT));
	KUNIT_EXPECT_TRUE(test, medusa_v4_message_allowed(
		MEDUSA_STATE_POLICY_INSTALL, MEDUSA_MSG_POLICY_COMMIT));
	KUNIT_EXPECT_TRUE(test, medusa_v4_message_allowed(
		MEDUSA_STATE_READY, MEDUSA_MSG_DECISION_REPLY));
	KUNIT_EXPECT_FALSE(test, medusa_v4_message_allowed(
		MEDUSA_STATE_DEGRADED, MEDUSA_MSG_DECISION_REPLY));
}

static void protocol_frame_layout_is_stable(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (size_t)MEDUSA_FRAME_HEADER_SIZE,
			sizeof(struct medusa_frame_header));
	KUNIT_EXPECT_EQ(test, (size_t)MEDUSA_TLV_HEADER_SIZE,
			sizeof(struct medusa_tlv));
	KUNIT_EXPECT_EQ(test, (size_t)16, MEDUSA_TLV_ALIGN_UP(9));
	KUNIT_EXPECT_EQ(test, (size_t)16, MEDUSA_TLV_ALIGN_UP(16));
}

static void protocol_rejects_unknown_answer_code(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL, medusa_v4_validate_answer(2));
	KUNIT_EXPECT_EQ(test, -EINVAL, medusa_v4_validate_answer(0));
}

static void protocol_validates_fallback_policy(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0, medusa_v4_validate_fallback_policy(
		MEDUSA_FALLBACK_BASELINE_ALLOW));
	KUNIT_EXPECT_EQ(test, 0, medusa_v4_validate_fallback_policy(
		MEDUSA_FALLBACK_ONLINE_REQUIRED));
	KUNIT_EXPECT_EQ(test, -EINVAL,
			medusa_v4_validate_fallback_policy(3));
}

static void protocol_negotiates_optional_features(struct kunit *test)
{
	u64 enabled = 0;

	KUNIT_EXPECT_EQ(test, 0, medusa_v4_negotiate_features(
		MEDUSA_REQUIRED_FEATURES, BIT_ULL(63), &enabled));
	KUNIT_EXPECT_EQ(test, (u64)MEDUSA_REQUIRED_FEATURES, enabled);
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP, medusa_v4_negotiate_features(
		BIT_ULL(63), 0, &enabled));
}

static void decision_counters_attribute_final_verdicts(struct kunit *test)
{
	struct medusa_decision_counter_snapshot counters;
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;
	enum medusa_fallback_policy policy;
	int error;

	med_decide_result(&test_event_type, &event, &subject, &object);

	policy = MEDUSA_FALLBACK_ONLINE_REQUIRED;
	error = medusa_set_fallback_policy(&test_event_type, policy);
	KUNIT_ASSERT_EQ(test, 0, error);
	med_decide_result(&test_event_type, &event, &subject, &object);

	policy = MEDUSA_FALLBACK_BASELINE_ALLOW;
	error = medusa_set_fallback_policy(&test_event_type, policy);
	KUNIT_ASSERT_EQ(test, 0, error);
	KUNIT_ASSERT_EQ(test, 0, med_register_authserver(&fake_server));
	delegated_answer = MED_ALLOW;
	med_decide_result(&test_event_type, &event, &subject, &object);
	delegated_answer = MED_DENY;
	med_decide_result(&test_event_type, &event, &subject, &object);
	delegated_answer = MED_ERR;
	delegated_unavailable = MEDUSA_DECISION_TIMED_OUT;
	med_decide_result(&test_event_type, &event, &subject, &object);
	delegated_answer = (enum medusa_answer_t)2;
	med_decide_result(&test_event_type, &event, &subject, &object);
	med_unregister_authserver(&fake_server);

	medusa_decision_counters_snapshot(&test_event_type, &counters);
	KUNIT_EXPECT_EQ(test, (u64)6, counters.total);
	KUNIT_EXPECT_EQ(test, (u64)4, counters.delegated);
	KUNIT_EXPECT_EQ(test, (u64)2, counters.auth_server);
	KUNIT_EXPECT_EQ(test, (u64)2, counters.baseline);
	KUNIT_EXPECT_EQ(test, (u64)1, counters.online_required);
	KUNIT_EXPECT_EQ(test, (u64)3, counters.allowed);
	KUNIT_EXPECT_EQ(test, (u64)3, counters.denied);
	KUNIT_EXPECT_EQ(test, (u64)1, counters.timed_out);
	KUNIT_EXPECT_EQ(test, (u64)1, counters.invalid_replies);
	KUNIT_EXPECT_EQ(test, counters.total,
			counters.cached + counters.auth_server +
			counters.baseline + counters.online_required +
			counters.invalid_replies);
}

static void decision_counter_wrap_is_well_defined(struct kunit *test)
{
	struct medusa_decision_counter_snapshot counters;
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;

	atomic64_set(&test_event_type.decision_counters.total, ~0ULL);
	med_decide_result(&test_event_type, &event, &subject, &object);
	medusa_decision_counters_snapshot(&test_event_type, &counters);

	KUNIT_EXPECT_EQ(test, (u64)0, counters.total);
}

static void monitoring_cache_accounting_is_explicit(struct kunit *test)
{
	struct medusa_decision_counter_snapshot counters;

	KUNIT_EXPECT_FALSE(test,
			   medusa_event_fallback_requires_decision(
				   &test_event_type));
	KUNIT_EXPECT_FALSE(test,
			   medusa_event_monitoring_check(&test_event_type, false));
	KUNIT_EXPECT_TRUE(test,
			  medusa_event_monitoring_check(&test_event_type, true));
	KUNIT_EXPECT_FALSE(test,
			   medusa_event_monitoring_check(&test_event_type, false));
	KUNIT_ASSERT_EQ(test, 0,
			medusa_set_fallback_policy(
				&test_event_type,
				MEDUSA_FALLBACK_BASELINE_DENY));
	KUNIT_EXPECT_TRUE(test,
			  medusa_event_fallback_requires_decision(
				  &test_event_type));
	KUNIT_EXPECT_TRUE(test,
			  medusa_event_monitoring_check(&test_event_type, false));
	KUNIT_ASSERT_EQ(test, 0,
			medusa_set_fallback_policy(
				&test_event_type,
				MEDUSA_FALLBACK_ONLINE_REQUIRED));
	KUNIT_EXPECT_TRUE(test,
			  medusa_event_fallback_requires_decision(
				  &test_event_type));
	medusa_event_set_enforced(&test_event_type,
				  MEDUSA_DELEGATION_CONDITIONAL);
	medusa_decision_counters_snapshot(&test_event_type, &counters);

	KUNIT_EXPECT_TRUE(test, READ_ONCE(test_event_type.enforced));
	KUNIT_EXPECT_EQ(test, MEDUSA_DELEGATION_CONDITIONAL,
			READ_ONCE(test_event_type.delegation_context));
	KUNIT_EXPECT_EQ(test, (u64)4, counters.evaluations);
	KUNIT_EXPECT_EQ(test, (u64)2, counters.cached);
	KUNIT_EXPECT_EQ(test, (u64)2, counters.total);
	KUNIT_EXPECT_EQ(test, (u64)0, counters.auth_server);
	KUNIT_EXPECT_EQ(test, (u64)2, counters.allowed);
	KUNIT_EXPECT_EQ(test, (u64)0, counters.denied);
	KUNIT_EXPECT_EQ(test, counters.total,
			counters.cached + counters.auth_server +
			counters.baseline + counters.online_required +
			counters.invalid_replies);
}

static void delegation_context_names_are_stable(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "none",
			  medusa_delegation_context_name(
				  MEDUSA_DELEGATION_NONE));
	KUNIT_EXPECT_STREQ(test, "sleepable",
			  medusa_delegation_context_name(
				  MEDUSA_DELEGATION_SLEEPABLE));
	KUNIT_EXPECT_STREQ(test, "lock_bound",
			  medusa_delegation_context_name(
				  MEDUSA_DELEGATION_LOCK_BOUND));
	KUNIT_EXPECT_STREQ(test, "conditional",
			  medusa_delegation_context_name(
				  MEDUSA_DELEGATION_CONDITIONAL));
	KUNIT_EXPECT_STREQ(test, "invalid",
			  medusa_delegation_context_name(
				  (enum medusa_delegation_context)-1));
}

static void protocol_counters_are_cumulative(struct kunit *test)
{
	struct medusa_protocol_counter_snapshot before;
	struct medusa_protocol_counter_snapshot after;

	medusa_protocol_counters_snapshot(&before);
	medusa_protocol_counter_inc(MEDUSA_PROTOCOL_REPLIES);
	medusa_protocol_counter_inc(MEDUSA_PROTOCOL_LEASE_RENEWALS);
	medusa_protocol_counter_inc(MEDUSA_PROTOCOL_MALFORMED_MESSAGES);
	medusa_protocol_counter_inc(MEDUSA_PROTOCOL_INVALID_ANSWERS);
	medusa_protocol_counter_inc(MEDUSA_PROTOCOL_UNKNOWN_COMMANDS);
	medusa_protocol_counter_inc(MEDUSA_PROTOCOL_UNKNOWN_REQUESTS);
	medusa_protocol_counter_inc(MEDUSA_PROTOCOL_STALE_REQUESTS);
	medusa_protocol_counters_snapshot(&after);

	KUNIT_EXPECT_EQ(test, before.replies + 1, after.replies);
	KUNIT_EXPECT_EQ(test, before.lease_renewals + 1,
			after.lease_renewals);
	KUNIT_EXPECT_EQ(test, before.malformed_messages + 1,
			after.malformed_messages);
	KUNIT_EXPECT_EQ(test, before.invalid_answers + 1,
			after.invalid_answers);
	KUNIT_EXPECT_EQ(test, before.unknown_commands + 1,
			after.unknown_commands);
	KUNIT_EXPECT_EQ(test, before.unknown_requests + 1,
			after.unknown_requests);
	KUNIT_EXPECT_EQ(test, before.stale_requests + 1,
			after.stale_requests);
}

static void protocol_error_names_are_stable(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "malformed_message",
			   medusa_protocol_error_name(MEDUSA_PROTOCOL_MALFORMED_MESSAGES));
	KUNIT_EXPECT_STREQ(test, "invalid_answer",
			   medusa_protocol_error_name(MEDUSA_PROTOCOL_INVALID_ANSWERS));
	KUNIT_EXPECT_STREQ(test, "unknown_command",
			   medusa_protocol_error_name(MEDUSA_PROTOCOL_UNKNOWN_COMMANDS));
	KUNIT_EXPECT_STREQ(test, "unknown_request",
			   medusa_protocol_error_name(MEDUSA_PROTOCOL_UNKNOWN_REQUESTS));
	KUNIT_EXPECT_STREQ(test, "stale_request",
			   medusa_protocol_error_name(MEDUSA_PROTOCOL_STALE_REQUESTS));
	KUNIT_EXPECT_STREQ(test, "invalid",
			   medusa_protocol_error_name(MEDUSA_PROTOCOL_REPLIES));
}

static struct kunit_case comm_test_cases[] = {
	KUNIT_CASE(decide_without_server_uses_baseline_and_preserves_monitoring),
	KUNIT_CASE(baseline_deny_is_enforced_without_server),
	KUNIT_CASE(baseline_deny_cannot_be_overridden_by_server),
	KUNIT_CASE(online_required_denies_without_server),
	KUNIT_CASE(decide_propagates_allow),
	KUNIT_CASE(decide_propagates_deny),
	KUNIT_CASE(decide_uses_baseline_when_server_is_unreachable),
	KUNIT_CASE(online_required_denies_when_server_is_unreachable),
	KUNIT_CASE(unhealthy_server_uses_baseline_without_contact),
	KUNIT_CASE(decide_denies_unsupported_server_answer),
	KUNIT_CASE(authoritative_server_results_can_validate),
	KUNIT_CASE(fallback_results_cannot_validate),
	KUNIT_CASE(incomplete_server_results_cannot_validate),
	KUNIT_CASE(decision_metadata_names_are_stable),
	KUNIT_CASE(fallback_policy_rejects_invalid_values),
	KUNIT_CASE(fallback_policy_names_are_stable),
	KUNIT_CASE(protocol_accepts_supported_answers),
	KUNIT_CASE(protocol_enforces_state_machine),
	KUNIT_CASE(protocol_frame_layout_is_stable),
	KUNIT_CASE(protocol_rejects_unknown_answer_code),
	KUNIT_CASE(protocol_validates_fallback_policy),
	KUNIT_CASE(protocol_negotiates_optional_features),
	KUNIT_CASE(decision_counters_attribute_final_verdicts),
	KUNIT_CASE(decision_counter_wrap_is_well_defined),
	KUNIT_CASE(monitoring_cache_accounting_is_explicit),
	KUNIT_CASE(delegation_context_names_are_stable),
	KUNIT_CASE(protocol_counters_are_cumulative),
	KUNIT_CASE(protocol_error_names_are_stable),
	{}
};

static struct kunit_suite comm_test_suite = {
	.name = "medusa-comm-tests",
	.init = comm_test_init,
	.test_cases = comm_test_cases,
};

kunit_test_suite(comm_test_suite);

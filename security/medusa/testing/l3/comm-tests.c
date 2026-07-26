// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l3/registry.h"
#include "l4/protocol.h"

static enum medusa_answer_t delegated_answer;
static int decide_calls;
static int close_calls;
static int subject_unmonitor_calls;
static int object_unmonitor_calls;
static bool server_healthy;

static void fake_close(void)
{
	close_calls++;
}

static enum medusa_answer_t fake_decide(struct medusa_event_s *event,
					struct medusa_kobject_s *subject,
					struct medusa_kobject_s *object,
					bool *authserver_contacted)
{
	*authserver_contacted = true;
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
	KUNIT_EXPECT_FALSE(test, result.authserver_contacted);
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
	KUNIT_EXPECT_FALSE(test, result.authserver_contacted);
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

	KUNIT_ASSERT_EQ(test, 0,
			medusa_set_fallback_policy(
				&test_event_type,
				MEDUSA_FALLBACK_ONLINE_REQUIRED));
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
	int result;

	delegated_answer = server_answer;
	decide_calls = 0;
	close_calls = 0;
	result = med_register_authserver(&fake_server);
	KUNIT_ASSERT_EQ(test, 0, result);

	decision = med_decide_result(&test_event_type, &event, &subject,
				     &object);
	med_unregister_authserver(&fake_server);

	KUNIT_EXPECT_EQ(test, expected, decision.answer);
	KUNIT_EXPECT_EQ(test, expected_source, decision.source);
	KUNIT_EXPECT_EQ(test, unavailable, decision.unavailable);
	KUNIT_EXPECT_TRUE(test, decision.authserver_contacted);
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
	KUNIT_EXPECT_FALSE(test, result.authserver_contacted);
	KUNIT_EXPECT_EQ(test, 0, decide_calls);
}

static void decide_denies_unsupported_server_answer(struct kunit *test)
{
	expect_delegated_answer(test, (enum medusa_answer_t)2, MED_DENY,
				MEDUSA_DECISION_INVALID_REPLY,
				MEDUSA_AVAILABLE);
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

static void protocol_accepts_supported_answers(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0, medusa_comm_validate_authanswer(
		MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE, MED_ALLOW, true));
	KUNIT_EXPECT_EQ(test, 0, medusa_comm_validate_authanswer(
		MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE, MED_DENY, true));
	KUNIT_EXPECT_EQ(test, 0, medusa_comm_validate_authanswer(
		MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE, MED_ERR, true));
}

static void protocol_rejects_malformed_answer_lengths(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EMSGSIZE, medusa_comm_validate_authanswer(
		MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE - 1, MED_ALLOW, true));
	KUNIT_EXPECT_EQ(test, -EMSGSIZE, medusa_comm_validate_authanswer(
		MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE + 1, MED_ALLOW, true));
}

static void protocol_rejects_unknown_answer_code(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -EINVAL, medusa_comm_validate_authanswer(
		MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE, 2, true));
}

static void protocol_rejects_unknown_request_id(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, -ENOENT, medusa_comm_validate_authanswer(
		MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE, MED_ALLOW, false));
}

static void protocol_rejects_stale_request_id(struct kunit *test)
{
	bool request_pending = true;

	request_pending = false;
	KUNIT_EXPECT_EQ(test, -ENOENT, medusa_comm_validate_authanswer(
		MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE, MED_DENY,
		request_pending));
}

static void protocol_validates_decision_progress(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0,
			medusa_comm_validate_authrequest_progress(
				MEDUSA_COMM_AUTHREQUEST_PROGRESS_PAYLOAD_SIZE,
				true));
	KUNIT_EXPECT_EQ(test, -EMSGSIZE,
			medusa_comm_validate_authrequest_progress(
				MEDUSA_COMM_AUTHREQUEST_PROGRESS_PAYLOAD_SIZE - 1,
				true));
	KUNIT_EXPECT_EQ(test, -ENOENT,
			medusa_comm_validate_authrequest_progress(
				MEDUSA_COMM_AUTHREQUEST_PROGRESS_PAYLOAD_SIZE,
				false));
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
	KUNIT_CASE(fallback_policy_rejects_invalid_values),
	KUNIT_CASE(protocol_accepts_supported_answers),
	KUNIT_CASE(protocol_rejects_malformed_answer_lengths),
	KUNIT_CASE(protocol_rejects_unknown_answer_code),
	KUNIT_CASE(protocol_rejects_unknown_request_id),
	KUNIT_CASE(protocol_rejects_stale_request_id),
	KUNIT_CASE(protocol_validates_decision_progress),
	{}
};

static struct kunit_suite comm_test_suite = {
	.name = "medusa-comm-tests",
	.init = comm_test_init,
	.test_cases = comm_test_cases,
};

kunit_test_suite(comm_test_suite);

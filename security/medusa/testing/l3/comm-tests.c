// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l3/registry.h"
#include "l4/protocol.h"

static enum medusa_answer_t delegated_answer;
static int decide_calls;
static int close_calls;
static int subject_unmonitor_calls;
static int object_unmonitor_calls;

static void fake_close(void)
{
	close_calls++;
}

static enum medusa_answer_t fake_decide(struct medusa_event_s *event,
					struct medusa_kobject_s *subject,
					struct medusa_kobject_s *object)
{
	decide_calls++;
	return delegated_answer;
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
};

static void decide_without_server_allows_and_uncaches(struct kunit *test)
{
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;
	enum medusa_answer_t answer;

	subject_unmonitor_calls = 0;
	object_unmonitor_calls = 0;
	answer = med_decide(&test_event_type, &event, &subject, &object);

	KUNIT_EXPECT_EQ(test, MED_ALLOW, answer);
	KUNIT_EXPECT_EQ(test, 1, subject_unmonitor_calls);
	KUNIT_EXPECT_EQ(test, 1, object_unmonitor_calls);
}

static void expect_delegated_answer(struct kunit *test,
				    enum medusa_answer_t server_answer,
				    enum medusa_answer_t expected)
{
	struct medusa_event_s event = {};
	struct medusa_kobject_s subject;
	struct medusa_kobject_s object;
	enum medusa_answer_t answer;
	int result;

	delegated_answer = server_answer;
	decide_calls = 0;
	close_calls = 0;
	result = med_register_authserver(&fake_server);
	KUNIT_ASSERT_EQ(test, 0, result);

	answer = med_decide(&test_event_type, &event, &subject, &object);
	med_unregister_authserver(&fake_server);

	KUNIT_EXPECT_EQ(test, expected, answer);
	KUNIT_EXPECT_EQ(test, 1, decide_calls);
	KUNIT_EXPECT_PTR_EQ(test, &test_event_type, event.evtype_id);
	KUNIT_EXPECT_EQ(test, 1, close_calls);
}

static void decide_propagates_allow(struct kunit *test)
{
	expect_delegated_answer(test, MED_ALLOW, MED_ALLOW);
}

static void decide_propagates_deny(struct kunit *test)
{
	expect_delegated_answer(test, MED_DENY, MED_DENY);
}

static void decide_fails_open_when_server_is_unreachable(struct kunit *test)
{
	expect_delegated_answer(test, MED_ERR, MED_ALLOW);
}

static void decide_denies_unsupported_server_answer(struct kunit *test)
{
	expect_delegated_answer(test, (enum medusa_answer_t)2, MED_DENY);
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

static struct kunit_case comm_test_cases[] = {
	KUNIT_CASE(decide_without_server_allows_and_uncaches),
	KUNIT_CASE(decide_propagates_allow),
	KUNIT_CASE(decide_propagates_deny),
	KUNIT_CASE(decide_fails_open_when_server_is_unreachable),
	KUNIT_CASE(decide_denies_unsupported_server_answer),
	KUNIT_CASE(protocol_accepts_supported_answers),
	KUNIT_CASE(protocol_rejects_malformed_answer_lengths),
	KUNIT_CASE(protocol_rejects_unknown_answer_code),
	KUNIT_CASE(protocol_rejects_unknown_request_id),
	KUNIT_CASE(protocol_rejects_stale_request_id),
	{}
};

static struct kunit_suite comm_test_suite = {
	.name = "medusa-comm-tests",
	.test_cases = comm_test_cases,
};

kunit_test_suite(comm_test_suite);

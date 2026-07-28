// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l3/registry.h"

static int close_calls;
static int kclass_calls;
static int evtype_calls;
static bool server_healthy;
static enum medusa_health_reason server_health_reason;
static struct medusa_evtype_s *announced_event;

static void fake_close(void)
{
	close_calls++;
}

static int fake_add_kclass(struct medusa_kclass_s *kclass)
{
	kclass_calls++;
	return 0;
}

static int fake_add_evtype(struct medusa_evtype_s *evtype)
{
	evtype_calls++;
	if (!announced_event)
		announced_event = evtype;
	return 0;
}

static enum medusa_answer_t fake_decide(struct medusa_event_s *event,
					struct medusa_kobject_s *subject,
					struct medusa_kobject_s *object,
					struct medusa_authserver_decision *decision)
{
	decision->request_id = 1;
	decision->request_present = true;
	decision->contacted = true;
	return MED_ALLOW;
}

static bool fake_is_healthy(void)
{
	return server_healthy;
}

static enum medusa_health_reason fake_health_reason(void)
{
	return server_health_reason;
}

static struct medusa_authserver_s fake_server = {
	.name = "kunit-fake",
	.close = fake_close,
	.add_kclass = fake_add_kclass,
	.add_evtype = fake_add_evtype,
	.decide = fake_decide,
	.is_healthy = fake_is_healthy,
	.health_reason = fake_health_reason,
};

static struct medusa_authserver_s other_server = {
	.name = "kunit-other",
	.decide = fake_decide,
};

static void registry_prepare_replays_definitions(struct kunit *test)
{
	int result;

	kclass_calls = 0;
	evtype_calls = 0;
	announced_event = NULL;
	result = med_register_authserver_prepare(&fake_server);

	KUNIT_EXPECT_EQ(test, 0, result);
	KUNIT_EXPECT_GT(test, kclass_calls, 0);
	KUNIT_EXPECT_GT(test, evtype_calls, 0);
	KUNIT_EXPECT_FALSE(test, med_is_authserver_present());
}

static void registry_commits_staged_fallback_only_at_ready(struct kunit *test)
{
	enum medusa_fallback_policy original;

	announced_event = NULL;
	KUNIT_ASSERT_EQ(test, 0,
			med_register_authserver_prepare(&fake_server));
	KUNIT_ASSERT_NOT_NULL(test, announced_event);
	original = medusa_get_fallback_policy(announced_event);

	KUNIT_ASSERT_EQ(test, 0,
			med_authserver_handshake_begin(&fake_server));
	KUNIT_EXPECT_EQ(test, -EPERM,
			med_authserver_stage_fallback_policy(
				&other_server, announced_event,
				MEDUSA_FALLBACK_BASELINE_DENY));
	KUNIT_EXPECT_EQ(test, -ENOENT,
			med_authserver_stage_fallback_policy(
				&fake_server,
				(struct medusa_evtype_s *)&fake_server,
				MEDUSA_FALLBACK_BASELINE_DENY));
	KUNIT_ASSERT_EQ(test, 0,
			med_authserver_stage_fallback_policy(
				&fake_server, announced_event,
				MEDUSA_FALLBACK_BASELINE_DENY));
	KUNIT_EXPECT_EQ(test, original,
			medusa_get_fallback_policy(announced_event));

	KUNIT_ASSERT_EQ(test, 0, med_register_authserver(&fake_server));
	KUNIT_EXPECT_EQ(test, MEDUSA_FALLBACK_BASELINE_DENY,
			medusa_get_fallback_policy(announced_event));
	med_unregister_authserver(&fake_server);

	/* A later handshake safely reuses the preceding generation's old slot. */
	KUNIT_ASSERT_EQ(test, 0,
			med_register_authserver_prepare(&fake_server));
	KUNIT_ASSERT_EQ(test, 0,
			med_authserver_handshake_begin(&fake_server));
	KUNIT_ASSERT_EQ(test, 0,
			med_authserver_stage_fallback_policy(
				&fake_server, announced_event,
				MEDUSA_FALLBACK_ONLINE_REQUIRED));
	KUNIT_EXPECT_EQ(test, MEDUSA_FALLBACK_BASELINE_DENY,
			medusa_get_fallback_policy(announced_event));
	KUNIT_ASSERT_EQ(test, 0, med_register_authserver(&fake_server));
	KUNIT_EXPECT_EQ(test, MEDUSA_FALLBACK_ONLINE_REQUIRED,
			medusa_get_fallback_policy(announced_event));
	med_unregister_authserver(&fake_server);
	KUNIT_ASSERT_EQ(test, 0,
			medusa_set_fallback_policy(announced_event, original));
}

static void registry_aborts_staged_fallback_with_handshake(struct kunit *test)
{
	enum medusa_fallback_policy original;

	announced_event = NULL;
	KUNIT_ASSERT_EQ(test, 0,
			med_register_authserver_prepare(&fake_server));
	KUNIT_ASSERT_NOT_NULL(test, announced_event);
	original = medusa_get_fallback_policy(announced_event);
	KUNIT_ASSERT_EQ(test, 0,
			med_authserver_handshake_begin(&fake_server));
	KUNIT_ASSERT_EQ(test, 0,
			med_authserver_stage_fallback_policy(
				&fake_server, announced_event,
				MEDUSA_FALLBACK_ONLINE_REQUIRED));

	med_unregister_authserver(&fake_server);
	KUNIT_EXPECT_EQ(test, original,
			medusa_get_fallback_policy(announced_event));
}

static void registry_authserver_lifecycle(struct kunit *test)
{
	struct medusa_authserver_s *held;
	int initial_magic = medusa_authserver_magic;
	int result;

	close_calls = 0;
	fake_server.use_count = 0;
	other_server.use_count = 0;

	result = med_register_authserver(&fake_server);
	KUNIT_EXPECT_EQ(test, 0, result);
	KUNIT_EXPECT_TRUE(test, med_is_authserver_present());
	KUNIT_EXPECT_EQ(test, initial_magic + 1, medusa_authserver_magic);
	KUNIT_EXPECT_EQ(test, 1, fake_server.use_count);

	result = med_register_authserver(&other_server);
	KUNIT_EXPECT_EQ(test, -1, result);
	KUNIT_EXPECT_EQ(test, initial_magic + 1, medusa_authserver_magic);
	KUNIT_EXPECT_EQ(test, 0, other_server.use_count);

	held = med_get_authserver();
	KUNIT_EXPECT_PTR_EQ(test, &fake_server, held);
	KUNIT_EXPECT_EQ(test, 2, fake_server.use_count);

	med_unregister_authserver(&other_server);
	KUNIT_EXPECT_TRUE(test, med_is_authserver_present());
	KUNIT_EXPECT_EQ(test, initial_magic + 1, medusa_authserver_magic);

	med_put_authserver(held);
	KUNIT_EXPECT_EQ(test, 1, fake_server.use_count);
	KUNIT_EXPECT_EQ(test, 0, close_calls);

	med_unregister_authserver(&fake_server);
	KUNIT_EXPECT_FALSE(test, med_is_authserver_present());
	KUNIT_EXPECT_PTR_EQ(test, NULL, med_get_authserver());
	KUNIT_EXPECT_EQ(test, initial_magic + 2, medusa_authserver_magic);
	KUNIT_EXPECT_EQ(test, 0, fake_server.use_count);
	KUNIT_EXPECT_EQ(test, 1, close_calls);
}

static void registry_status_snapshots_lifecycle_and_health(struct kunit *test)
{
	struct medusa_registry_status status;
	u64 initial_generation = (u64)medusa_authserver_magic;

	medusa_registry_status_snapshot(&status);
	KUNIT_ASSERT_FALSE(test, status.connected);
	KUNIT_EXPECT_EQ(test, MEDUSA_AUTHSERVER_DISCONNECTED,
			status.server_state);
	KUNIT_EXPECT_FALSE(test, status.health_known);
	KUNIT_EXPECT_FALSE(test, status.healthy);
	KUNIT_EXPECT_EQ(test, MEDUSA_HEALTH_DISCONNECTED,
			status.health_reason);
	KUNIT_EXPECT_EQ(test, initial_generation, status.policy_generation);
	KUNIT_EXPECT_EQ(test, (u64)0, status.active_policy_generation);
	KUNIT_EXPECT_STREQ(test, "", status.server_name);

	close_calls = 0;
	fake_server.use_count = 0;
	server_healthy = false;
	server_health_reason = MEDUSA_HEALTH_DECISION_TIMEOUT;
	KUNIT_ASSERT_EQ(test, 0, med_register_authserver(&fake_server));

	medusa_registry_status_snapshot(&status);
	KUNIT_EXPECT_TRUE(test, status.connected);
	KUNIT_EXPECT_EQ(test, MEDUSA_AUTHSERVER_READY,
			status.server_state);
	KUNIT_EXPECT_TRUE(test, status.health_known);
	KUNIT_EXPECT_FALSE(test, status.healthy);
	KUNIT_EXPECT_EQ(test, MEDUSA_HEALTH_DECISION_TIMEOUT,
			status.health_reason);
	KUNIT_EXPECT_EQ(test, initial_generation + 1,
			status.policy_generation);
	KUNIT_EXPECT_EQ(test, initial_generation + 1,
			status.active_policy_generation);
	KUNIT_EXPECT_EQ(test, initial_generation + 1,
			status.last_ready_policy_generation);
	KUNIT_EXPECT_STREQ(test, "kunit-fake", status.server_name);
	KUNIT_EXPECT_EQ(test, 1, fake_server.use_count);

	server_healthy = true;
	server_health_reason = MEDUSA_HEALTHY;
	medusa_registry_status_snapshot(&status);
	KUNIT_EXPECT_TRUE(test, status.healthy);
	KUNIT_EXPECT_EQ(test, MEDUSA_HEALTHY, status.health_reason);

	med_unregister_authserver(&fake_server);
	medusa_registry_status_snapshot(&status);
	KUNIT_EXPECT_FALSE(test, status.connected);
	KUNIT_EXPECT_EQ(test, MEDUSA_AUTHSERVER_DISCONNECTED,
			status.server_state);
	KUNIT_EXPECT_EQ(test, initial_generation + 2,
			status.policy_generation);
	KUNIT_EXPECT_EQ(test, (u64)0, status.active_policy_generation);
	KUNIT_EXPECT_EQ(test, initial_generation + 1,
			status.last_ready_policy_generation);
	KUNIT_EXPECT_EQ(test, 1, close_calls);
}

static void registry_reports_handshake_before_policy_ready(struct kunit *test)
{
	struct medusa_registry_status status;
	u64 initial_generation = (u64)medusa_authserver_magic;

	fake_server.use_count = 0;
	close_calls = 0;
	KUNIT_ASSERT_EQ(test, 0,
			med_authserver_handshake_begin(&fake_server));
	KUNIT_EXPECT_EQ(test, -EBUSY,
			med_authserver_handshake_begin(&other_server));

	medusa_registry_status_snapshot(&status);
	KUNIT_EXPECT_FALSE(test, status.connected);
	KUNIT_EXPECT_EQ(test, MEDUSA_AUTHSERVER_HANDSHAKING,
			status.server_state);
	KUNIT_EXPECT_STREQ(test, "kunit-fake", status.server_name);
	KUNIT_EXPECT_EQ(test, (u64)0, status.active_policy_generation);

	KUNIT_ASSERT_EQ(test, 0, med_register_authserver(&fake_server));
	medusa_registry_status_snapshot(&status);
	KUNIT_EXPECT_TRUE(test, status.connected);
	KUNIT_EXPECT_EQ(test, MEDUSA_AUTHSERVER_READY,
			status.server_state);
	KUNIT_EXPECT_EQ(test, initial_generation + 1,
			status.active_policy_generation);

	med_unregister_authserver(&fake_server);
	KUNIT_EXPECT_EQ(test, 1, close_calls);
}

static void registry_can_abort_incomplete_handshake(struct kunit *test)
{
	struct medusa_registry_status status;
	u64 initial_generation = (u64)medusa_authserver_magic;

	close_calls = 0;
	KUNIT_ASSERT_EQ(test, 0,
			med_authserver_handshake_begin(&fake_server));
	med_unregister_authserver(&fake_server);
	medusa_registry_status_snapshot(&status);

	KUNIT_EXPECT_FALSE(test, status.connected);
	KUNIT_EXPECT_EQ(test, MEDUSA_AUTHSERVER_DISCONNECTED,
			status.server_state);
	KUNIT_EXPECT_EQ(test, initial_generation, status.policy_generation);
	KUNIT_EXPECT_EQ(test, (u64)0, status.active_policy_generation);
	KUNIT_EXPECT_EQ(test, 0, close_calls);
}

static void registry_state_names_are_stable(struct kunit *test)
{
	const char *name;

	name = medusa_authserver_state_name(MEDUSA_AUTHSERVER_DISCONNECTED);
	KUNIT_EXPECT_STREQ(test, "disconnected", name);
	name = medusa_authserver_state_name(MEDUSA_AUTHSERVER_HANDSHAKING);
	KUNIT_EXPECT_STREQ(test, "handshaking", name);
	name = medusa_authserver_state_name(MEDUSA_AUTHSERVER_READY);
	KUNIT_EXPECT_STREQ(test, "ready", name);
	name = medusa_authserver_state_name(99);
	KUNIT_EXPECT_STREQ(test, "invalid", name);
}

static void registry_status_reports_unknown_optional_health(struct kunit *test)
{
	struct medusa_registry_status status;

	other_server.use_count = 0;
	KUNIT_ASSERT_EQ(test, 0, med_register_authserver(&other_server));
	medusa_registry_status_snapshot(&status);

	KUNIT_EXPECT_TRUE(test, status.connected);
	KUNIT_EXPECT_FALSE(test, status.health_known);
	KUNIT_EXPECT_FALSE(test, status.healthy);
	KUNIT_EXPECT_STREQ(test, "kunit-other", status.server_name);

	med_unregister_authserver(&other_server);
}

static struct kunit_case registry_test_cases[] = {
	KUNIT_CASE(registry_prepare_replays_definitions),
	KUNIT_CASE(registry_commits_staged_fallback_only_at_ready),
	KUNIT_CASE(registry_aborts_staged_fallback_with_handshake),
	KUNIT_CASE(registry_authserver_lifecycle),
	KUNIT_CASE(registry_status_snapshots_lifecycle_and_health),
	KUNIT_CASE(registry_reports_handshake_before_policy_ready),
	KUNIT_CASE(registry_can_abort_incomplete_handshake),
	KUNIT_CASE(registry_status_reports_unknown_optional_health),
	KUNIT_CASE(registry_state_names_are_stable),
	{}
};

static struct kunit_suite registry_test_suite = {
	.name = "medusa-registry-tests",
	.test_cases = registry_test_cases,
};

kunit_test_suite(registry_test_suite);

// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l3/health.h"

static void health_circuit_breaker_transitions_and_recovers(struct kunit *test)
{
	struct medusa_server_health health = MEDUSA_SERVER_HEALTH_INIT;

	KUNIT_EXPECT_FALSE(test, medusa_server_health_is_healthy(&health));
	KUNIT_EXPECT_EQ(test, MEDUSA_HEALTH_DISCONNECTED,
			medusa_server_health_reason(&health));

	medusa_server_health_mark_healthy(&health);
	KUNIT_EXPECT_TRUE(test, medusa_server_health_is_healthy(&health));
	KUNIT_EXPECT_EQ(test, MEDUSA_HEALTHY,
			medusa_server_health_reason(&health));

	KUNIT_EXPECT_TRUE(test,
			  medusa_server_health_mark_unhealthy(
				  &health, MEDUSA_HEALTH_DECISION_TIMEOUT));
	KUNIT_EXPECT_FALSE(test, medusa_server_health_is_healthy(&health));
	KUNIT_EXPECT_EQ(test, MEDUSA_HEALTH_DECISION_TIMEOUT,
			medusa_server_health_reason(&health));

	KUNIT_EXPECT_FALSE(test,
			   medusa_server_health_mark_unhealthy(
				   &health, MEDUSA_HEALTH_OVERLOADED));
	KUNIT_EXPECT_EQ(test, MEDUSA_HEALTH_OVERLOADED,
			medusa_server_health_reason(&health));

	medusa_server_health_mark_healthy(&health);
	KUNIT_EXPECT_TRUE(test, medusa_server_health_is_healthy(&health));
	KUNIT_EXPECT_EQ(test, MEDUSA_HEALTHY,
			medusa_server_health_reason(&health));
}

static void health_reason_names_are_stable(struct kunit *test)
{
	const char *name;

	name = medusa_health_reason_name(MEDUSA_HEALTHY);
	KUNIT_EXPECT_STREQ(test, "healthy", name);
	name = medusa_health_reason_name(MEDUSA_HEALTH_DISCONNECTED);
	KUNIT_EXPECT_STREQ(test, "disconnected", name);
	name = medusa_health_reason_name(MEDUSA_HEALTH_DECISION_TIMEOUT);
	KUNIT_EXPECT_STREQ(test, "decision_timeout", name);
	name = medusa_health_reason_name(MEDUSA_HEALTH_OVERLOADED);
	KUNIT_EXPECT_STREQ(test, "overloaded", name);
	name = medusa_health_reason_name((enum medusa_health_reason)-1);
	KUNIT_EXPECT_STREQ(test, "invalid", name);
}

static struct kunit_case health_test_cases[] = {
	KUNIT_CASE(health_circuit_breaker_transitions_and_recovers),
	KUNIT_CASE(health_reason_names_are_stable),
	{}
};

static struct kunit_suite health_test_suite = {
	.name = "medusa-health-tests",
	.test_cases = health_test_cases,
};

kunit_test_suite(health_test_suite);

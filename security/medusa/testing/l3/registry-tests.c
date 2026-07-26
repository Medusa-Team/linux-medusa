// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l3/registry.h"

static int close_calls;
static int kclass_calls;
static int evtype_calls;

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
	return 0;
}

static enum medusa_answer_t fake_decide(struct medusa_event_s *event,
					struct medusa_kobject_s *subject,
					struct medusa_kobject_s *object,
					struct medusa_authserver_decision *decision)
{
	decision->contacted = true;
	return MED_ALLOW;
}

static struct medusa_authserver_s fake_server = {
	.name = "kunit-fake",
	.close = fake_close,
	.add_kclass = fake_add_kclass,
	.add_evtype = fake_add_evtype,
	.decide = fake_decide,
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
	result = med_register_authserver_prepare(&fake_server);

	KUNIT_EXPECT_EQ(test, 0, result);
	KUNIT_EXPECT_GT(test, kclass_calls, 0);
	KUNIT_EXPECT_GT(test, evtype_calls, 0);
	KUNIT_EXPECT_FALSE(test, med_is_authserver_present());
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

static struct kunit_case registry_test_cases[] = {
	KUNIT_CASE(registry_prepare_replays_definitions),
	KUNIT_CASE(registry_authserver_lifecycle),
	{}
};

static struct kunit_suite registry_test_suite = {
	.name = "medusa-registry-tests",
	.test_cases = registry_test_cases,
};

kunit_test_suite(registry_test_suite);

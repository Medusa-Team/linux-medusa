// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include <uapi/linux/medusa.h>

#include "l3/decision_cache.h"
#include "l3/kobject.h"
#include "l3/med_model.h"

struct medusa_decision_cache_test_context {
	int generation;
};

static int medusa_decision_cache_test_init(struct kunit *test)
{
	struct medusa_decision_cache_test_context *context;

	context = kunit_kzalloc(test, sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	context->generation = READ_ONCE(medusa_authserver_magic);
	test->priv = context;
	medusa_decision_cache_reset();
	return 0;
}

static void medusa_decision_cache_test_exit(struct kunit *test)
{
	struct medusa_decision_cache_test_context *context = test->priv;

	medusa_decision_cache_reset();
	WRITE_ONCE(medusa_authserver_magic, context->generation);
}

static void domain_cache_prefers_exact_rules(struct kunit *test)
{
	struct medusa_evtype_s event = {};
	struct medusa_evtype_s other = {};
	enum medusa_answer_t answer = MED_ERR;
	u64 generation = 101;
	bool found;
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_begin(generation));
	ret = medusa_decision_cache_stage(&event, MEDUSA_POLICY_DOMAIN_ANY,
					  MEDUSA_POLICY_DOMAIN_ANY,
					  MEDUSA_POLICY_SELECTOR_ANY,
					  MED_ALLOW);
	KUNIT_ASSERT_EQ(test, 0, ret);
	ret = medusa_decision_cache_stage(&event, 7, 9, 11, MED_DENY);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_prepare(generation));
	WRITE_ONCE(medusa_authserver_magic, generation);
	medusa_decision_cache_publish(generation);

	found = medusa_decision_cache_lookup(&event, 7, 9, 11, &answer);
	KUNIT_EXPECT_TRUE(test, found);
	KUNIT_EXPECT_EQ(test, MED_DENY, answer);
	found = medusa_decision_cache_lookup(&event, 1, 2, 3, &answer);
	KUNIT_EXPECT_TRUE(test, found);
	KUNIT_EXPECT_EQ(test, MED_ALLOW, answer);
	found = medusa_decision_cache_lookup(&other, 7, 9, 11, &answer);
	KUNIT_EXPECT_FALSE(test, found);
}

static void stale_generation_never_matches(struct kunit *test)
{
	struct medusa_evtype_s event = {};
	enum medusa_answer_t answer = MED_ERR;
	u64 generation = 201;
	bool found;
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_begin(generation));
	ret = medusa_decision_cache_stage(&event, 1, 2, 3, MED_DENY);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_prepare(generation));
	WRITE_ONCE(medusa_authserver_magic, generation);
	medusa_decision_cache_publish(generation);
	found = medusa_decision_cache_lookup(&event, 1, 2, 3, &answer);
	KUNIT_ASSERT_TRUE(test, found);

	WRITE_ONCE(medusa_authserver_magic, generation + 1);
	found = medusa_decision_cache_lookup(&event, 1, 2, 3, &answer);
	KUNIT_EXPECT_FALSE(test, found);
}

static void replacement_is_not_visible_before_publish(struct kunit *test)
{
	struct medusa_evtype_s event = {};
	enum medusa_answer_t answer = MED_ERR;
	u64 generation = 301;
	bool found;
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_begin(generation));
	ret = medusa_decision_cache_stage(&event, 1, 2, 3, MED_DENY);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_prepare(generation));
	WRITE_ONCE(medusa_authserver_magic, generation);
	medusa_decision_cache_publish(generation);

	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_begin(generation + 1));
	ret = medusa_decision_cache_stage(&event, 1, 2, 3, MED_ALLOW);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_prepare(generation + 1));
	found = medusa_decision_cache_lookup(&event, 1, 2, 3, &answer);
	KUNIT_ASSERT_TRUE(test, found);
	KUNIT_EXPECT_EQ(test, MED_DENY, answer);

	WRITE_ONCE(medusa_authserver_magic, generation + 1);
	medusa_decision_cache_publish(generation + 1);
	found = medusa_decision_cache_lookup(&event, 1, 2, 3, &answer);
	KUNIT_ASSERT_TRUE(test, found);
	KUNIT_EXPECT_EQ(test, MED_ALLOW, answer);
}

static void duplicate_batch_is_atomic(struct kunit *test)
{
	struct medusa_evtype_s event = {};
	const struct medusa_domain_rule_spec rules[] = {
		{ 1, 2, 3, MED_ALLOW },
		{ 1, 2, 3, MED_DENY },
	};
	enum medusa_answer_t answer = MED_ERR;
	u64 generation = 401;
	bool found;
	int ret;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_begin(generation));
	ret = medusa_decision_cache_stage_rules(&event, rules,
						ARRAY_SIZE(rules));
	KUNIT_EXPECT_EQ(test, -EEXIST, ret);
	KUNIT_ASSERT_EQ(test, 0,
			medusa_decision_cache_prepare(generation));
	WRITE_ONCE(medusa_authserver_magic, generation);
	medusa_decision_cache_publish(generation);
	found = medusa_decision_cache_lookup(&event, 1, 2, 3, &answer);
	KUNIT_EXPECT_FALSE(test, found);
}

static struct kunit_case medusa_decision_cache_test_cases[] = {
	KUNIT_CASE(domain_cache_prefers_exact_rules),
	KUNIT_CASE(stale_generation_never_matches),
	KUNIT_CASE(replacement_is_not_visible_before_publish),
	KUNIT_CASE(duplicate_batch_is_atomic),
	{}
};

static struct kunit_suite medusa_decision_cache_test_suite = {
	.name = "medusa-decision-cache-tests",
	.init = medusa_decision_cache_test_init,
	.exit = medusa_decision_cache_test_exit,
	.test_cases = medusa_decision_cache_test_cases,
};

kunit_test_suite(medusa_decision_cache_test_suite);

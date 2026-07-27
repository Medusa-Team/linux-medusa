// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l1/inode.h"
#include "l2/kobject_path_guard.h"

static void path_guard_rejects_invalid_inputs(struct kunit *test)
{
	struct medusa_l1_inode_s context;

	KUNIT_ASSERT_TRUE(test, path_guard_is_ready());
	medusa_inode_context_init(&context);
	KUNIT_EXPECT_FALSE(test, path_guard_path_add(NULL, &context));
	KUNIT_EXPECT_FALSE(test, path_guard_path_add("/invalid", NULL));
	KUNIT_EXPECT_FALSE(test,
			   path_guard_path_is_allowed(NULL, &context));
	KUNIT_EXPECT_FALSE(test,
			   path_guard_path_is_allowed("/invalid", NULL));
	KUNIT_EXPECT_FALSE(test, path_guard_path_remove(NULL, &context));
	KUNIT_EXPECT_FALSE(test, path_guard_path_remove("/invalid", NULL));
	KUNIT_EXPECT_FALSE(test, path_guard_has_entries(NULL));
	KUNIT_EXPECT_EQ(test, -EINVAL, path_guard_free(NULL));
	KUNIT_EXPECT_FALSE(test, path_guard_has_entries(&context));
}

static void path_guard_add_lookup_remove(struct kunit *test)
{
	struct medusa_l1_inode_s context;

	medusa_inode_context_init(&context);
	KUNIT_EXPECT_FALSE(test,
			   path_guard_path_is_allowed("/srv/allowed", &context));
	KUNIT_ASSERT_TRUE(test,
			  path_guard_path_add("/srv/allowed", &context));
	KUNIT_EXPECT_TRUE(test,
			  path_guard_path_is_allowed("/srv/allowed", &context));
	KUNIT_EXPECT_FALSE(test,
			   path_guard_path_is_allowed("/srv/other", &context));
	KUNIT_EXPECT_TRUE(test, path_guard_has_entries(&context));

	KUNIT_ASSERT_TRUE(test,
			  path_guard_path_add("/srv/allowed", &context));
	KUNIT_EXPECT_FALSE(test,
			   path_guard_path_remove("/srv/other", &context));
	KUNIT_ASSERT_TRUE(test,
			  path_guard_path_remove("/srv/allowed", &context));
	KUNIT_EXPECT_FALSE(test,
			   path_guard_path_is_allowed("/srv/allowed", &context));
	KUNIT_EXPECT_FALSE(test, path_guard_has_entries(&context));
}

static void path_guard_entries_are_independent(struct kunit *test)
{
	struct medusa_l1_inode_s context;

	medusa_inode_context_init(&context);
	KUNIT_ASSERT_TRUE(test, path_guard_path_add("/one", &context));
	KUNIT_ASSERT_TRUE(test, path_guard_path_add("/two", &context));
	KUNIT_ASSERT_TRUE(test, path_guard_path_add("/three", &context));
	KUNIT_EXPECT_TRUE(test, path_guard_has_entries(&context));
	KUNIT_ASSERT_TRUE(test, path_guard_path_remove("/two", &context));
	KUNIT_EXPECT_TRUE(test, path_guard_path_is_allowed("/one", &context));
	KUNIT_EXPECT_FALSE(test, path_guard_path_is_allowed("/two", &context));
	KUNIT_EXPECT_TRUE(test,
			  path_guard_path_is_allowed("/three", &context));

	KUNIT_EXPECT_EQ(test, 0, path_guard_free(&context));
	KUNIT_EXPECT_FALSE(test, path_guard_has_entries(&context));
	KUNIT_EXPECT_EQ(test, 0, path_guard_free(&context));
}

static struct kunit_case path_guard_test_cases[] = {
	KUNIT_CASE(path_guard_rejects_invalid_inputs),
	KUNIT_CASE(path_guard_add_lookup_remove),
	KUNIT_CASE(path_guard_entries_are_independent),
	{}
};

static struct kunit_suite path_guard_test_suite = {
	.name = "medusa-path-guard-tests",
	.test_cases = path_guard_test_cases,
};

kunit_test_suite(path_guard_test_suite);

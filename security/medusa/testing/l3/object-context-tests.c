// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l1/inode.h"
#include "l1/ipc.h"

static void expect_default_object_context(struct kunit *test,
					  struct medusa_object_s *object)
{
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(object->vs.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(object->act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_EQ(test, (u64)0, object->cinfo.data[0]);
	KUNIT_EXPECT_EQ(test, 0, object->magic);
}

static void inode_context_initialization(struct kunit *test)
{
	struct medusa_l1_inode_s context;

	hash_init(context.path_guard);
	context.path_guard[0].first = (struct hlist_node *)&context;
	KUNIT_ASSERT_FALSE(test, hash_empty(context.path_guard));

	medusa_inode_context_init(&context);

	expect_default_object_context(test, &context.med_object);
	KUNIT_EXPECT_TRUE(test, hash_empty(context.path_guard));
}

static void ipc_context_initialization(struct kunit *test)
{
	static const unsigned int classes[] = {
		MED_IPC_SEM,
		MED_IPC_MSG,
		MED_IPC_SHM,
	};
	struct medusa_l1_ipc_s context;
	int i;

	for (i = 0; i < ARRAY_SIZE(classes); i++) {
		memset(&context, 0xff, sizeof(context));
		medusa_ipc_context_init(&context, classes[i]);

		expect_default_object_context(test, &context.med_object);
		KUNIT_EXPECT_EQ_MSG(test, classes[i], context.ipc_class,
				    "IPC class index %d", i);
	}
}

static struct kunit_case object_context_test_cases[] = {
	KUNIT_CASE(inode_context_initialization),
	KUNIT_CASE(ipc_context_initialization),
	{}
};

static struct kunit_suite object_context_test_suite = {
	.name = "medusa-object-context-tests",
	.test_cases = object_context_test_cases,
};

kunit_test_suite(object_context_test_suite);

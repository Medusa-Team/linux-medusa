// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l1/task.h"

static void task_context_monitored_initialization(struct kunit *test)
{
	struct medusa_l1_task_s context = {};

	med_magic_not_monitored(&context.med_object);
	medusa_task_context_init(&context, NULL,
				 MEDUSA_TASK_CONTEXT_MONITORED);

	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_object.vs.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_object.act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_subject.vss.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_subject.vsr.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_subject.vsw.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_subject.act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_EQ(test, 0, context.med_object.magic);
	KUNIT_EXPECT_EQ(test, 1, context.validation_depth_nesting);
#ifdef CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL
	KUNIT_EXPECT_PTR_EQ(test, NULL, context.self);
	KUNIT_EXPECT_EQ(test, 0, refcount_read(&context.rcu_cb_set));
#endif
}

static void task_context_unmonitored_initialization(struct kunit *test)
{
	struct medusa_l1_task_s context = {};

	medusa_task_context_init(&context, NULL,
				 MEDUSA_TASK_CONTEXT_UNMONITORED);

	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_object.vs.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_empty(context.med_object.act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_subject.vss.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_subject.vsr.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_subject.vsw.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_empty(context.med_subject.act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_EQ(test, MAGIC_NOT_MONITORED, context.med_object.magic);
	KUNIT_EXPECT_EQ(test, 1, context.validation_depth_nesting);
}

static void userspace_trigger_reenables_monitoring(struct kunit *test)
{
	struct medusa_l1_task_s context = {
		.audit = 1,
	};

	medusa_task_context_init(&context, NULL,
				 MEDUSA_TASK_CONTEXT_UNMONITORED);
	KUNIT_ASSERT_EQ(test, MAGIC_NOT_MONITORED, context.med_object.magic);

	medusa_task_context_enable_monitoring(&context);

	KUNIT_EXPECT_EQ(test, 0, context.med_object.magic);
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_object.act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_TRUE(test,
		bitmap_full(context.med_subject.act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_EQ(test, 1, context.audit);
}

static void task_context_inherits_parent_state(struct kunit *test)
{
	struct medusa_l1_task_s parent = {};
	struct medusa_l1_task_s child = {};

	init_med_object(&parent.med_object);
	init_med_subject(&parent.med_subject);
	vs_clearbit(parent.med_object.vs, 3);
	vs_clearbit(parent.med_subject.vss, 4);
	vs_clearbit(parent.med_subject.vsr, 5);
	vs_clearbit(parent.med_subject.vsw, 6);
	act_clearbit(parent.med_object.act, 7);
	act_clearbit(parent.med_subject.act, 8);
	parent.med_object.magic = 77;
	parent.med_object.cinfo.data[0] = 101;
	parent.med_subject.cinfo.data[0] = 202;
	parent.audit = 1;
	parent.luid = KUIDT_INIT(123);
	strscpy(parent.cmdline, "inherited command", sizeof(parent.cmdline));

	medusa_task_context_init(&child, &parent,
				 MEDUSA_TASK_CONTEXT_INHERIT);

	KUNIT_EXPECT_TRUE(test,
		bitmap_equal(child.med_object.vs.pack, parent.med_object.vs.pack,
			     CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_equal(child.med_object.act.pack, parent.med_object.act.pack,
			     CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_TRUE(test,
		bitmap_equal(child.med_subject.vss.pack, parent.med_subject.vss.pack,
			     CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_equal(child.med_subject.vsr.pack, parent.med_subject.vsr.pack,
			     CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_equal(child.med_subject.vsw.pack, parent.med_subject.vsw.pack,
			     CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
		bitmap_equal(child.med_subject.act.pack, parent.med_subject.act.pack,
			     CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_EQ(test, parent.med_object.magic, child.med_object.magic);
	KUNIT_EXPECT_EQ(test, parent.med_object.cinfo.data[0],
			child.med_object.cinfo.data[0]);
	KUNIT_EXPECT_EQ(test, parent.med_subject.cinfo.data[0],
			child.med_subject.cinfo.data[0]);
	KUNIT_EXPECT_EQ(test, parent.audit, child.audit);
	KUNIT_EXPECT_TRUE(test, uid_eq(parent.luid, child.luid));
	KUNIT_EXPECT_STREQ(test, parent.cmdline, child.cmdline);
	KUNIT_EXPECT_EQ(test, 1, child.validation_depth_nesting);
#ifdef CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL
	KUNIT_EXPECT_PTR_EQ(test, NULL, child.self);
	KUNIT_EXPECT_EQ(test, 0, refcount_read(&child.rcu_cb_set));
#endif
}

static struct kunit_case task_context_test_cases[] = {
	KUNIT_CASE(task_context_monitored_initialization),
	KUNIT_CASE(task_context_unmonitored_initialization),
	KUNIT_CASE(userspace_trigger_reenables_monitoring),
	KUNIT_CASE(task_context_inherits_parent_state),
	{}
};

static struct kunit_suite task_context_test_suite = {
	.name = "medusa-task-context-tests",
	.test_cases = task_context_test_cases,
};

kunit_test_suite(task_context_test_suite);

#include <kunit/test.h>
#include "l3/med_model.h"
#include "l1/task.h"

static void fake_med_object_init(struct medusa_object_s *med_object)
{
	vs_set(med_object->vs);
	vs_clearbit(med_object->vs, CONFIG_MEDUSA_VS - 1);
	vs_clearbit(med_object->vs, CONFIG_MEDUSA_VS - 2);
	vs_clearbit(med_object->vs, CONFIG_MEDUSA_VS - 3);
	vs_clearbit(med_object->vs, CONFIG_MEDUSA_VS - 4);

	act_clear(med_object->act);
	bitmap_set(med_object->act.pack, 0, CONFIG_MEDUSA_ACT - 4);

	med_object->magic = 1;
}

static void fake_med_subject_init(struct medusa_subject_s *med_subject)
{
	vs_set(med_subject->vsr);
	vs_clearbit(med_subject->vsr, CONFIG_MEDUSA_VS - 1);
	vs_clearbit(med_subject->vsr, CONFIG_MEDUSA_VS - 2);
	vs_clearbit(med_subject->vsr, CONFIG_MEDUSA_VS - 3);
	vs_clearbit(med_subject->vsr, CONFIG_MEDUSA_VS - 4);

	vs_set(med_subject->vsw);
	vs_clearbit(med_subject->vsw, CONFIG_MEDUSA_VS - 1);
	vs_clearbit(med_subject->vsw, CONFIG_MEDUSA_VS - 2);
	vs_clearbit(med_subject->vsw, CONFIG_MEDUSA_VS - 3);
	vs_clearbit(med_subject->vsw, CONFIG_MEDUSA_VS - 4);

	vs_set(med_subject->vss);
	vs_clearbit(med_subject->vss, CONFIG_MEDUSA_VS - 1);
	vs_clearbit(med_subject->vss, CONFIG_MEDUSA_VS - 2);
	vs_clearbit(med_subject->vss, CONFIG_MEDUSA_VS - 3);
	vs_clearbit(med_subject->vss, CONFIG_MEDUSA_VS - 4);

	act_clear(med_subject->act);
	bitmap_set(med_subject->act.pack, 0, CONFIG_MEDUSA_ACT - 4);
}

static void is_med_magic_valid_not_changed(struct kunit *test)
{
	struct medusa_l1_task_s task;

	fake_med_object_init(&task.med_object);
	task.med_object.magic = medusa_authserver_magic;
	KUNIT_EXPECT_TRUE(test, is_med_magic_valid(&task.med_object));
}

static void is_med_magic_valid_changed_invalid(struct kunit *test)
{
	struct medusa_l1_task_s task;

	fake_med_object_init(&task.med_object);
	task.med_object.magic = medusa_authserver_magic == 1 ? 2 : 1;
	KUNIT_EXPECT_FALSE(test, is_med_magic_valid(&task.med_object));
}

static void med_magic_validate_success(struct kunit *test)
{
	struct medusa_l1_task_s task;
	int old_magic;

	fake_med_object_init(&task.med_object);
	task.med_object.magic = medusa_authserver_magic == 1 ? 2 : 1;
	old_magic = task.med_object.magic;

	med_magic_validate(&task.med_object);

	KUNIT_EXPECT_NE(test, old_magic, task.med_object.magic);
	KUNIT_EXPECT_TRUE(test, is_med_magic_valid(&task.med_object));
}

static void med_magic_invalidate_success(struct kunit *test)
{
	struct medusa_l1_task_s task;
	fake_med_object_init(&task.med_object);

	med_magic_invalidate(&task.med_object);

	KUNIT_EXPECT_EQ(test, 0, task.med_object.magic);
}

static void init_med_object_success(struct kunit *test)
{
	struct medusa_object_s *med_object;
	struct medusa_l1_task_s task;

	init_med_object(&task.med_object);
	med_object = &task.med_object;

	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_object->vs.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_object->act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_EQ(test, (u_int64_t)0, med_object->cinfo.data[0]);
	KUNIT_EXPECT_EQ(test, 0, med_object->magic);
}

static void unmonitor_med_object_success(struct kunit *test)
{
	struct medusa_object_s old_med_object;
	struct medusa_object_s *med_object;
	struct medusa_l1_task_s task;

	fake_med_object_init(&task.med_object);
	bitmap_copy(old_med_object.vs.pack, task.med_object.vs.pack, CONFIG_MEDUSA_VS);
	bitmap_copy(old_med_object.act.pack, task.med_object.act.pack, CONFIG_MEDUSA_ACT);

	unmonitor_med_object(&task.med_object);
	med_object = &task.med_object;

	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_object.vs.pack,
	      med_object->vs.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_object->vs.pack, CONFIG_MEDUSA_VS));

	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_object.act.pack,
	      med_object->act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_empty(med_object->act.pack, CONFIG_MEDUSA_ACT));
}

static void init_med_subject_success(struct kunit *test)
{
	struct medusa_subject_s *med_subject;
	struct medusa_l1_task_s task;

	init_med_subject(&task.med_subject);
	med_subject = &task.med_subject;

	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vsr.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vsw.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vss.pack, CONFIG_MEDUSA_VS));

	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->act.pack, CONFIG_MEDUSA_ACT));

	KUNIT_EXPECT_EQ(test, (u_int64_t)0, med_subject->cinfo.data[0]);
}

static void unmonitor_med_subject_success(struct kunit *test)
{
	struct medusa_subject_s old_med_subject;
	struct medusa_subject_s *med_subject;
	struct medusa_l1_task_s task;

	fake_med_subject_init(&task.med_subject);
	bitmap_copy(old_med_subject.vss.pack, task.med_subject.vss.pack, CONFIG_MEDUSA_VS);
	bitmap_copy(old_med_subject.vsr.pack, task.med_subject.vsr.pack, CONFIG_MEDUSA_VS);
	bitmap_copy(old_med_subject.vsw.pack, task.med_subject.vsw.pack, CONFIG_MEDUSA_VS);
	bitmap_copy(old_med_subject.act.pack, task.med_subject.act.pack, CONFIG_MEDUSA_ACT);

	unmonitor_med_subject(&task.med_subject);
	med_subject = &task.med_subject;

	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_subject.vsr.pack,
	      med_subject->vsr.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_subject.vsw.pack,
	      med_subject->vsw.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_subject.vss.pack,
	      med_subject->vss.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vsr.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vsw.pack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vss.pack, CONFIG_MEDUSA_VS));

	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_subject.act.pack,
	      med_subject->act.pack, CONFIG_MEDUSA_ACT));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_empty(med_subject->act.pack, CONFIG_MEDUSA_ACT));
}

static void action_bitmap_boundary_bits(struct kunit *test)
{
	struct act_t act;

	act_clear(act);
	act_setbit(act, 0);
	act_setbit(act, CONFIG_MEDUSA_ACT - 1);

	KUNIT_EXPECT_TRUE(test, act_testbit(act, 0));
	KUNIT_EXPECT_TRUE(test, act_testbit(act, CONFIG_MEDUSA_ACT - 1));
	KUNIT_EXPECT_EQ(test, 2,
			bitmap_weight(act.pack, CONFIG_MEDUSA_ACT));

	act_clearbit(act, 0);
	act_clearbit(act, CONFIG_MEDUSA_ACT - 1);
	KUNIT_EXPECT_FALSE(test, act_testbit(act, 0));
	KUNIT_EXPECT_FALSE(test, act_testbit(act, CONFIG_MEDUSA_ACT - 1));
	KUNIT_EXPECT_TRUE(test, bitmap_empty(act.pack, CONFIG_MEDUSA_ACT));
}

static void magic_generation_rollover_invalidates_context(struct kunit *test)
{
	struct medusa_object_s object;
	int saved_magic = medusa_authserver_magic;

	init_med_object(&object);
	medusa_authserver_magic = 41;
	med_magic_validate(&object);
	KUNIT_ASSERT_TRUE(test, is_med_magic_valid(&object));

	medusa_authserver_magic = 42;
	KUNIT_EXPECT_FALSE(test, is_med_magic_valid(&object));
	med_magic_validate(&object);
	KUNIT_EXPECT_TRUE(test, is_med_magic_valid(&object));
	KUNIT_EXPECT_EQ(test, 42, object.magic);

	medusa_authserver_magic = saved_magic;
}

static void not_monitored_context_survives_normal_generation_changes(
	struct kunit *test)
{
	struct medusa_object_s object;
	int saved_magic = medusa_authserver_magic;

	init_med_object(&object);
	med_magic_not_monitored(&object);
	KUNIT_ASSERT_EQ(test, MAGIC_NOT_MONITORED, object.magic);
	KUNIT_ASSERT_TRUE(test, is_med_magic_valid(&object));
	KUNIT_ASSERT_FALSE(test, is_med_magic_monitored(&object));

	medusa_authserver_magic++;
	med_magic_validate(&object);
	med_magic_invalidate(&object);
	KUNIT_EXPECT_EQ(test, MAGIC_NOT_MONITORED, object.magic);
	KUNIT_EXPECT_TRUE(test, is_med_magic_valid(&object));

	medusa_authserver_magic = saved_magic;
}

static void forced_invalidation_reenables_monitoring(struct kunit *test)
{
	struct medusa_object_s object;

	init_med_object(&object);
	med_magic_not_monitored(&object);
	med_magic_invalidate_force(&object);

	KUNIT_EXPECT_EQ(test, 0, object.magic);
	KUNIT_EXPECT_TRUE(test, is_med_magic_monitored(&object));
	KUNIT_EXPECT_EQ(test, medusa_authserver_magic == 0,
			is_med_magic_valid(&object));
}

static struct kunit_case add_base_tc[] = {
	KUNIT_CASE(is_med_magic_valid_not_changed),
	KUNIT_CASE(is_med_magic_valid_changed_invalid),
	KUNIT_CASE(med_magic_validate_success),
	KUNIT_CASE(med_magic_invalidate_success),
	KUNIT_CASE(init_med_object_success),
	KUNIT_CASE(unmonitor_med_object_success),
	KUNIT_CASE(init_med_subject_success),
	KUNIT_CASE(unmonitor_med_subject_success),
	KUNIT_CASE(action_bitmap_boundary_bits),
	KUNIT_CASE(magic_generation_rollover_invalidates_context),
	KUNIT_CASE(not_monitored_context_survives_normal_generation_changes),
	KUNIT_CASE(forced_invalidation_reenables_monitoring),
	{}
};

static struct kunit_suite add_base_suite = {
	.name = "medusa-model-tests",
	.test_cases = add_base_tc,
};
kunit_test_suite(add_base_suite);

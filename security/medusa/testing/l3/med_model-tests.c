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
	int medusa_authserver_magic = 1;

	fake_med_object_init(&task.med_object);
	KUNIT_EXPECT_EQ(test, 1, _is_med_magic_valid(&task.med_object, medusa_authserver_magic));
}

static void is_med_magic_valid_changed_invalid(struct kunit *test)
{
	struct medusa_l1_task_s task;
	int medusa_authserver_magic = 2;

	fake_med_object_init(&task.med_object);
	KUNIT_EXPECT_EQ(test, 0, _is_med_magic_valid(&task.med_object, medusa_authserver_magic));
}

static void med_magic_validate_success(struct kunit *test)
{
	struct medusa_l1_task_s task;
	int old_magic;
	int medusa_authserver_magic = 2;

	fake_med_object_init(&task.med_object);
	old_magic = task.med_object.magic;

	_med_magic_validate(&task.med_object, medusa_authserver_magic);

	KUNIT_EXPECT_NE(test, old_magic, task.med_object.magic);
	KUNIT_EXPECT_EQ(test, 1, _is_med_magic_valid(&task.med_object, medusa_authserver_magic));
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

static struct kunit_case add_base_tc[] = {
	KUNIT_CASE(is_med_magic_valid_not_changed),
	KUNIT_CASE(is_med_magic_valid_changed_invalid),
	KUNIT_CASE(med_magic_validate_success),
	KUNIT_CASE(med_magic_invalidate_success),
	KUNIT_CASE(init_med_object_success),
	KUNIT_CASE(unmonitor_med_object_success),
	KUNIT_CASE(med_magic_validate_success),
	KUNIT_CASE(init_med_subject_success),
	KUNIT_CASE(unmonitor_med_subject_success),
	{}
};

static struct kunit_suite add_base_suite = {
	.name = "medusa-model-tests",
	.test_cases = add_base_tc,
};
kunit_test_suite(add_base_suite);

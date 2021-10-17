#include <kunit/test.h>
#include <linux/medusa/l3/med_model.h>
#include <linux/medusa/l1/task.h>

static void fake_med_object_init(struct medusa_object_s *med_object)
{
	vs_set(med_object->vs);
	vs_clearbit(med_object->vs, CONFIG_MEDUSA_VS - 1);
	vs_clearbit(med_object->vs, CONFIG_MEDUSA_VS - 2);
	vs_clearbit(med_object->vs, CONFIG_MEDUSA_VS - 3);
	vs_clearbit(med_object->vs, CONFIG_MEDUSA_VS - 4);
	med_object->act = 0x000000ff;
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

	med_subject->act = 0x000000ff;
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
	    bitmap_full(med_object->vs.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_object->act);
	KUNIT_EXPECT_EQ(test, (u_int64_t)0, med_object->cinfo.data[0]);
	KUNIT_EXPECT_EQ(test, 0, med_object->magic);
}

static void unmonitor_med_object_success(struct kunit *test)
{
	struct medusa_object_s old_med_object;
	struct medusa_object_s *med_object;
	struct medusa_l1_task_s task;

	fake_med_object_init(&task.med_object);
	old_med_object.vs = task.med_object.vs;
	old_med_object.act = task.med_object.act;

	unmonitor_med_object(&task.med_object);

	med_object = &task.med_object;
	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_object.vs.vspack,
	      med_object->vs.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_object->vs.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_NE(test, old_med_object.act, med_object->act);
	KUNIT_EXPECT_EQ(test, 0U, med_object->act);
}

static void init_med_subject_success(struct kunit *test)
{
	struct medusa_subject_s *med_subject;
	struct medusa_l1_task_s task;

	init_med_subject(&task.med_subject);

	med_subject = &task.med_subject;
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vsr.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vsw.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vss.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_subject->act);
	KUNIT_EXPECT_EQ(test, (u_int64_t)0, med_subject->cinfo.data[0]);
}

static void unmonitor_med_subject_success(struct kunit *test)
{
	struct medusa_subject_s old_med_subject;
	struct medusa_subject_s *med_subject;
	struct medusa_l1_task_s task;

	fake_med_subject_init(&task.med_subject);
	old_med_subject.vss = task.med_subject.vss;
	old_med_subject.vsr = task.med_subject.vsr;
	old_med_subject.vsw = task.med_subject.vsw;
	old_med_subject.act = task.med_subject.act;

	unmonitor_med_subject(&task.med_subject);

	med_subject = &task.med_subject;
	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_subject.vsr.vspack,
	      med_subject->vsr.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_subject.vsw.vspack,
	      med_subject->vsw.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_FALSE(test, bitmap_equal(old_med_subject.vss.vspack,
	      med_subject->vss.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vsr.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vsw.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_TRUE(test,
	    bitmap_full(med_subject->vss.vspack, CONFIG_MEDUSA_VS));
	KUNIT_EXPECT_NE(test, old_med_subject.act, med_subject->act);
	KUNIT_EXPECT_EQ(test, 0U, med_subject->act);
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

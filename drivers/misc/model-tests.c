#include <kunit/test.h>
#include <linux/medusa/l3/model.h>
#include <linux/medusa/l1/task.h>


static void fake_med_object_init(struct medusa_object_s *med_object)
{
	med_object->vs = 0x000000ff;
	med_object->act = 0x000000ff;
	med_object->magic = 1;
}

static void fake_med_subject_init(struct medusa_subject_s *med_subject)
{
	med_subject->vsr = 0x000000ff;
	med_subject->vsw = 0x000000ff;
	med_subject->vss = 0x000000ff;
	med_subject->act = 0x000000ff;
}

static void is_med_magic_valid_not_changed(struct kunit *test)
{
	struct medusa_l1_task_s task;
	int medusa_authserver_magic = 1;

	fake_med_object_init(&task.med_object);
	KUNIT_EXPECT_EQ(test, 1, MED_MAGIC_VALID(&task));
}

static void is_med_magic_valid_changed_invalid(struct kunit *test)
{
	struct medusa_l1_task_s task;
	int medusa_authserver_magic = 2;

	fake_med_object_init(&task.med_object);
	KUNIT_EXPECT_EQ(test, 0, MED_MAGIC_VALID(&task));
}

static void med_magic_validate_success(struct kunit *test)
{
	struct medusa_l1_task_s task;
	int old_magic;
	int medusa_authserver_magic = 2;

	fake_med_object_init(&task.med_object);
	old_magic = task.med_object.magic;

	MED_MAGIC_VALIDATE(&task);

	KUNIT_EXPECT_NE(test, old_magic, task.med_object.magic);
	KUNIT_EXPECT_EQ(test, 1, MED_MAGIC_VALID(&task));
}

static void med_magic_invalidate_success(struct kunit *test)
{
	struct medusa_l1_task_s task;
	fake_med_object_init(&task.med_object);

	MED_MAGIC_INVALIDATE(&task);

	KUNIT_EXPECT_EQ(test, 0, task.med_object.magic);
}

static void init_med_object_success(struct kunit *test)
{
	struct medusa_object_s *med_object;
	struct medusa_l1_task_s task;
	INIT_MEDUSA_OBJECT_VARS(&task);

	med_object = &task.med_object;
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_object->vs);
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

	UNMONITOR_MEDUSA_OBJECT_VARS(&task);

	med_object = &task.med_object;
	KUNIT_EXPECT_NE(test, old_med_object.vs, med_object->vs);
	KUNIT_EXPECT_NE(test, old_med_object.act, med_object->act);
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_object->vs);
	KUNIT_EXPECT_EQ(test, 0U, med_object->act);
}

static void init_med_subject_success(struct kunit *test)
{
	struct medusa_subject_s *med_subject;
	struct medusa_l1_task_s task;
	INIT_MEDUSA_SUBJECT_VARS(&task);

	med_subject = &task.med_subject;
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_subject->vss);
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_subject->vsr);
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_subject->vsw);
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

	UNMONITOR_MEDUSA_SUBJECT_VARS(&task);

	med_subject = &task.med_subject;
	KUNIT_EXPECT_NE(test, old_med_subject.vss, med_subject->vss);
	KUNIT_EXPECT_NE(test, old_med_subject.vsr, med_subject->vsr);
	KUNIT_EXPECT_NE(test, old_med_subject.vsw, med_subject->vsw);
	KUNIT_EXPECT_NE(test, old_med_subject.act, med_subject->act);
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_subject->vss);
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_subject->vsr);
	KUNIT_EXPECT_EQ(test, ALL_VS_ALLOWED, med_subject->vsw);
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

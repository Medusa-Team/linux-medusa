#include <kunit/test.h>
#include "l3/med_model.h"

static void vs_intersects_empty(struct kunit *test)
{
	struct vs_t a, b;
	vs_clear(a);
	vs_clear(b);

	KUNIT_EXPECT_FALSE(test, vs_intersects(a,b));
}

static void vs_intersects_one_bit_intersects(struct kunit *test)
{
	struct vs_t a, b;
	vs_set(a);
	vs_clear(b);
	vs_setbit(b, 8);

	KUNIT_EXPECT_TRUE(test, vs_intersects(a,b));
}

static void vs_intersects_partial_intersect(struct kunit *test)
{
	struct vs_t a, b;
	vs_set(a);
	vs_set(b);
	vs_clearbit(a, 0);
	vs_clearbit(a, 1);
	vs_clearbit(a, 2);
	vs_clearbit(a, 3);
	vs_clearbit(b, CONFIG_MEDUSA_VS - 1);
	vs_clearbit(b, CONFIG_MEDUSA_VS - 2);
	vs_clearbit(b, CONFIG_MEDUSA_VS - 3);
	vs_clearbit(b, CONFIG_MEDUSA_VS - 4);

	KUNIT_EXPECT_TRUE(test, vs_intersects(a,b));
}

static void vs_intersects_full_intersect(struct kunit *test)
{
	struct vs_t a, b;
	vs_set(a);
	vs_set(b);
	vs_clearbit(a, 0);
	vs_clearbit(a, 1);
	vs_clearbit(a, 2);
	vs_clearbit(a, 3);

	KUNIT_EXPECT_TRUE(test, vs_intersects(a,b));
}

static void vs_intersects_disjoin_not_intersects(struct kunit *test)
{
	struct vs_t a, b;
	vs_set(a);
	vs_clearbit(a, 0);
	vs_clearbit(a, 1);
	vs_clearbit(a, 2);
	vs_clearbit(a, 3);
	vs_complement(b, a);

	KUNIT_EXPECT_FALSE(test, vs_intersects(a,b));
}

static void vs_bitmap_boundary_bits(struct kunit *test)
{
	struct vs_t vs;

	vs_clear(vs);
	vs_setbit(vs, 0);
	vs_setbit(vs, CONFIG_MEDUSA_VS - 1);

	KUNIT_EXPECT_TRUE(test, test_bit(0, vs.pack));
	KUNIT_EXPECT_TRUE(test, test_bit(CONFIG_MEDUSA_VS - 1, vs.pack));
	KUNIT_EXPECT_EQ(test, 2, bitmap_weight(vs.pack, CONFIG_MEDUSA_VS));

	vs_clearbit(vs, 0);
	vs_clearbit(vs, CONFIG_MEDUSA_VS - 1);
	KUNIT_EXPECT_TRUE(test, bitmap_empty(vs.pack, CONFIG_MEDUSA_VS));
}

struct vs_access_case {
	const char *name;
	unsigned int requested;
	bool see;
	bool read;
	bool write;
	bool allowed;
};

static void vs_access_permissions(struct kunit *test)
{
	static const struct vs_access_case cases[] = {
		{ "none", 0, false, false, false, true },
		{ "see", MEDUSA_VS_SEE, true, false, false, true },
		{ "see missing", MEDUSA_VS_SEE, false, true, true, false },
		{ "read", MEDUSA_VS_READ, false, true, false, true },
		{ "read missing", MEDUSA_VS_READ, true, false, true, false },
		{ "write", MEDUSA_VS_WRITE, false, false, true, true },
		{ "write missing", MEDUSA_VS_WRITE, true, true, false, false },
		{ "all", MEDUSA_VS_SEE | MEDUSA_VS_READ | MEDUSA_VS_WRITE,
		  true, true, true, true },
		{ "all missing see",
		  MEDUSA_VS_SEE | MEDUSA_VS_READ | MEDUSA_VS_WRITE,
		  false, true, true, false },
		{ "all missing read",
		  MEDUSA_VS_SEE | MEDUSA_VS_READ | MEDUSA_VS_WRITE,
		  true, false, true, false },
		{ "all missing write",
		  MEDUSA_VS_SEE | MEDUSA_VS_READ | MEDUSA_VS_WRITE,
		  true, true, false, false },
	};
	struct medusa_subject_s subject;
	struct medusa_object_s object;
	int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		const struct vs_access_case *c = &cases[i];

		vs_clear(subject.vss);
		vs_clear(subject.vsr);
		vs_clear(subject.vsw);
		vs_clear(object.vs);
		vs_setbit(object.vs, 7);
		if (c->see)
			vs_setbit(subject.vss, 7);
		if (c->read)
			vs_setbit(subject.vsr, 7);
		if (c->write)
			vs_setbit(subject.vsw, 7);

		KUNIT_EXPECT_EQ_MSG(test, c->allowed,
			medusa_vs_access_allowed(&subject, &object,
						 c->requested),
			"case %s", c->name);
	}
}

static void vs_access_uses_any_common_space(struct kunit *test)
{
	struct medusa_subject_s subject;
	struct medusa_object_s object;

	vs_clear(subject.vss);
	vs_clear(subject.vsr);
	vs_clear(subject.vsw);
	vs_clear(object.vs);
	vs_setbit(object.vs, 1);
	vs_setbit(object.vs, CONFIG_MEDUSA_VS - 1);
	vs_setbit(subject.vss, CONFIG_MEDUSA_VS - 1);
	vs_setbit(subject.vsr, 1);
	vs_setbit(subject.vsw, CONFIG_MEDUSA_VS - 1);

	KUNIT_EXPECT_TRUE(test,
		medusa_vs_access_allowed(&subject, &object,
			MEDUSA_VS_SEE | MEDUSA_VS_READ | MEDUSA_VS_WRITE));
}

static struct kunit_case add_base_tc[] = {
	KUNIT_CASE(vs_intersects_empty),
	KUNIT_CASE(vs_intersects_one_bit_intersects),
	KUNIT_CASE(vs_intersects_partial_intersect),
	KUNIT_CASE(vs_intersects_full_intersect),
	KUNIT_CASE(vs_intersects_disjoin_not_intersects),
	KUNIT_CASE(vs_bitmap_boundary_bits),
	KUNIT_CASE(vs_access_permissions),
	KUNIT_CASE(vs_access_uses_any_common_space),
	{}
};

static struct kunit_suite add_base_suite = {
	.name = "medusa-vsmodel-tests",
	.test_cases = add_base_tc,
};
kunit_test_suite(add_base_suite);

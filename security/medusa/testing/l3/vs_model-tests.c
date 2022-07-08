#include <kunit/test.h>
#include "l3/vs_model.h"

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

static struct kunit_case add_base_tc[] = {
	KUNIT_CASE(vs_intersects_empty),
	KUNIT_CASE(vs_intersects_one_bit_intersects),
	KUNIT_CASE(vs_intersects_partial_intersect),
	KUNIT_CASE(vs_intersects_full_intersect),
	KUNIT_CASE(vs_intersects_disjoin_not_intersects),
	{}
};

static struct kunit_suite add_base_suite = {
	.name = "medusa-vsmodel-tests",
	.test_cases = add_base_tc,
};
kunit_test_suite(add_base_suite);

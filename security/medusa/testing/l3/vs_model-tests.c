#include <kunit/test.h>
#include <linux/medusa/l3/vs_model.h>

#if VSPACK_LENGTH > 1
	#define MULTIPLE_VSPACKS
#endif

static void vs_intersects_empty(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0UL;
	b.vspack[0] = 0UL;

	KUNIT_EXPECT_FALSE(test, vs_intersects(a,b));
}

static void vs_intersects_one_bit_intersects(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0xffff0000;
	b.vspack[0] = 0x00100000;

	KUNIT_EXPECT_TRUE(test, vs_intersects(a,b));
}

static void vs_intersects_partial_intersect(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0x00ff0000;
	b.vspack[0] = 0x000abaaa;

	KUNIT_EXPECT_TRUE(test, vs_intersects(a,b));
}

static void vs_intersects_full_intersect(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0xffff0000;
	b.vspack[0] = 0xffffff00;

	KUNIT_EXPECT_TRUE(test, vs_intersects(a,b));
}

static void vs_intersects_disjoin_not_intersects(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0xffff0000;
	b.vspack[0] = ~a.vspack[0];

	KUNIT_EXPECT_FALSE(test, vs_intersects(a,b));
}

#ifdef MULTIPLE_VSPACKS
static void vs_intersects_multiple_vspacks_empty(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0UL;
	b.vspack[0] = 0UL;
	a.vspack[1] = 0UL;
	b.vspack[1] = 0UL;

	KUNIT_EXPECT_FALSE(test, vs_intersects(a,b));
}

static void vs_intersects_multiple_vspacks_no_match(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0UL;
	b.vspack[0] = 0xffffffff;
	a.vspack[1] = 0xffffffff;
	b.vspack[1] = 0UL;

	KUNIT_EXPECT_FALSE(test, vs_intersects(a,b));
}

static void vs_intersects_multiple_vspacks_first_matches(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0x00000011;
	b.vspack[0] = 0x00000010;
	a.vspack[1] = 0x00500000;
	b.vspack[1] = 0x01000000;

	KUNIT_EXPECT_TRUE(test, vs_intersects(a,b));
}

static void vs_intersects_multiple_vspacks_second_matches(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0x00000001;
	b.vspack[0] = 0x00000010;
	a.vspack[1] = 0xff000000;
	b.vspack[1] = 0x01000000;

	KUNIT_EXPECT_TRUE(test, vs_intersects(b,a));
}

static void vs_intersects_multiple_vspacks_both_matches(struct kunit *test)
{
	vs_t a, b;
	a.vspack[0] = 0xffff0000;
	b.vspack[0] = 0xff000000;
	a.vspack[1] = 0x02000000;
	b.vspack[1] = 0x04000000;

	KUNIT_EXPECT_TRUE(test, vs_intersects(a,b));
}
#endif

static struct kunit_case add_base_tc[] = {
	KUNIT_CASE(vs_intersects_empty),
	KUNIT_CASE(vs_intersects_one_bit_intersects),
	KUNIT_CASE(vs_intersects_partial_intersect),
	KUNIT_CASE(vs_intersects_full_intersect),
	KUNIT_CASE(vs_intersects_disjoin_not_intersects),
#ifdef MULTIPLE_VSPACKS
	KUNIT_CASE(vs_intersects_multiple_vspacks_empty),
	KUNIT_CASE(vs_intersects_multiple_vspacks_no_match),
	KUNIT_CASE(vs_intersects_multiple_vspacks_first_matches),
	KUNIT_CASE(vs_intersects_multiple_vspacks_second_matches),
	KUNIT_CASE(vs_intersects_multiple_vspacks_both_matches),
#endif
	{}
};

static struct kunit_suite add_base_suite = {
	.name = "medusa-vsmodel-tests",
	.test_cases = add_base_tc,
};
kunit_test_suite(add_base_suite);

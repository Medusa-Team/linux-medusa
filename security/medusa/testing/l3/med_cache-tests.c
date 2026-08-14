// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l3/med_cache.h"

static void cache_growth_supports_boundary_allocation(struct kunit *test)
{
	const size_t allocation_size = 1U << 15;
	unsigned char *memory;
	int result;

	result = med_cache_register(allocation_size);
	KUNIT_ASSERT_EQ(test, 0, result);

	memory = med_cache_alloc_size(allocation_size);
	KUNIT_ASSERT_NOT_NULL(test, memory);
	memory[0] = 0x5a;
	memory[allocation_size - 1] = 0xa5;
	KUNIT_EXPECT_EQ(test, (unsigned char)0x5a, memory[0]);
	KUNIT_EXPECT_EQ(test, (unsigned char)0xa5,
			memory[allocation_size - 1]);

	med_cache_free(memory);
}

static struct kunit_case med_cache_test_cases[] = {
	KUNIT_CASE(cache_growth_supports_boundary_allocation),
	{}
};

static struct kunit_suite med_cache_test_suite = {
	.name = "medusa-cache-tests",
	.test_cases = med_cache_test_cases,
};

kunit_test_suite(med_cache_test_suite);

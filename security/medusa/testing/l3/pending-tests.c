// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l3/pending.h"

static int pending_test_init(struct kunit *test)
{
	medusa_pending_request_cancel_all(MED_ERR);
	KUNIT_ASSERT_EQ(test, 0U, medusa_pending_request_count());
	return 0;
}

static void pending_test_exit(struct kunit *test)
{
	(void)test;
	medusa_pending_request_cancel_all(MED_ERR);
}

static void pending_requests_have_independent_ids_and_answers(struct kunit *test)
{
	struct medusa_pending_request first;
	struct medusa_pending_request second;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_register(&first, 17));
	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_register(&second, 17));
	KUNIT_EXPECT_NE(test, 0ULL, first.id);
	KUNIT_EXPECT_NE(test, first.id, second.id);
	KUNIT_EXPECT_EQ(test, 2U, medusa_pending_request_count());

	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_complete(second.id, 17,
							MED_DENY));
	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_complete(first.id, 17,
							MED_ALLOW));
	KUNIT_EXPECT_EQ(test, MED_ALLOW,
			medusa_pending_request_wait(&first));
	KUNIT_EXPECT_EQ(test, MED_DENY,
			medusa_pending_request_wait(&second));
	KUNIT_EXPECT_EQ(test, 0U, medusa_pending_request_count());
}

static void pending_request_rejects_wrong_generation(struct kunit *test)
{
	struct medusa_pending_request request;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_register(&request, 41));
	KUNIT_EXPECT_EQ(test, -ESTALE,
			medusa_pending_request_complete(request.id, 40,
							MED_ALLOW));
	KUNIT_EXPECT_EQ(test, 1U, medusa_pending_request_count());
	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_complete(request.id, 41,
							MED_DENY));
	KUNIT_EXPECT_EQ(test, MED_DENY,
			medusa_pending_request_wait(&request));
}

static void
pending_request_rejects_unknown_and_duplicate_replies(struct kunit *test)
{
	struct medusa_pending_request request;

	KUNIT_EXPECT_EQ(test, -ENOENT,
			medusa_pending_request_complete(0xdeadbeefULL, 1,
							MED_ALLOW));
	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_register(&request, 1));
	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_complete(request.id, 1,
							MED_ALLOW));
	KUNIT_EXPECT_EQ(test, -ENOENT,
			medusa_pending_request_complete(request.id, 1,
							MED_DENY));
	KUNIT_EXPECT_EQ(test, MED_ALLOW,
			medusa_pending_request_wait(&request));
}

static void pending_disconnect_completes_all_requests(struct kunit *test)
{
	struct medusa_pending_request first;
	struct medusa_pending_request second;

	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_register(&first, 7));
	KUNIT_ASSERT_EQ(test, 0,
			medusa_pending_request_register(&second, 7));

	medusa_pending_request_cancel_all(MED_ERR);

	KUNIT_EXPECT_EQ(test, MED_ERR, medusa_pending_request_wait(&first));
	KUNIT_EXPECT_EQ(test, MED_ERR, medusa_pending_request_wait(&second));
	KUNIT_EXPECT_EQ(test, 0U, medusa_pending_request_count());
}

static void pending_request_table_is_bounded(struct kunit *test)
{
	struct medusa_pending_request *requests;
	struct medusa_pending_request **request_list;
	struct medusa_pending_request overflow;
	unsigned int index;

	request_list = kunit_kcalloc(test, MEDUSA_PENDING_REQUEST_LIMIT,
				    sizeof(*request_list), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, request_list);

	for (index = 0; index < MEDUSA_PENDING_REQUEST_LIMIT; index++) {
		requests = kunit_kzalloc(test, sizeof(*requests), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, requests);
		request_list[index] = requests;
		KUNIT_ASSERT_EQ(test, 0,
				medusa_pending_request_register(request_list[index],
								9));
	}

	KUNIT_EXPECT_EQ(test, -ENOSPC,
			medusa_pending_request_register(&overflow, 9));
	KUNIT_EXPECT_EQ(test, MEDUSA_PENDING_REQUEST_LIMIT,
			medusa_pending_request_count());

	medusa_pending_request_cancel_all(MED_ERR);
	for (index = 0; index < MEDUSA_PENDING_REQUEST_LIMIT; index++)
		KUNIT_EXPECT_EQ(test, MED_ERR,
				medusa_pending_request_wait(request_list[index]));
}

static struct kunit_case pending_test_cases[] = {
	KUNIT_CASE(pending_requests_have_independent_ids_and_answers),
	KUNIT_CASE(pending_request_rejects_wrong_generation),
	KUNIT_CASE(pending_request_rejects_unknown_and_duplicate_replies),
	KUNIT_CASE(pending_disconnect_completes_all_requests),
	KUNIT_CASE(pending_request_table_is_bounded),
	{}
};

static struct kunit_suite pending_test_suite = {
	.name = "medusa-pending-request-tests",
	.init = pending_test_init,
	.exit = pending_test_exit,
	.test_cases = pending_test_cases,
};

kunit_test_suite(pending_test_suite);

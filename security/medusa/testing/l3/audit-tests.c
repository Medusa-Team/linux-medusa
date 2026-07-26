// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "l2/audit_medusa.h"
#include "l2/l2.h"

static void audit_answer_names_are_bounded(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "ERROR",
			  medusa_audit_answer_name(MED_ERR));
	KUNIT_EXPECT_STREQ(test, "DENY",
			  medusa_audit_answer_name(MED_DENY));
	KUNIT_EXPECT_STREQ(test, "ALLOW",
			  medusa_audit_answer_name(MED_ALLOW));
	KUNIT_EXPECT_STREQ(test, "INVALID",
			  medusa_audit_answer_name(
				  (enum medusa_answer_t)-2));
	KUNIT_EXPECT_STREQ(test, "INVALID",
			  medusa_audit_answer_name(
				  (enum medusa_answer_t)4));
}

static void lsm_returns_preserve_stacked_denials(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0, lsm_retval(MED_ALLOW, 0));
	KUNIT_EXPECT_EQ(test, -EACCES, lsm_retval(MED_DENY, 0));
	KUNIT_EXPECT_EQ(test, 0, lsm_retval(MED_ERR, 0));
	KUNIT_EXPECT_EQ(test, -EIDRM, lsm_retval(MED_ALLOW, -EIDRM));
	KUNIT_EXPECT_EQ(test, -EIDRM, lsm_retval(MED_DENY, -EIDRM));
}

static void audit_decision_tracks_source_and_contact(struct kunit *test)
{
	struct medusa_audit_data mad = {};
	struct medusa_decision_result result = {
		.answer = MED_ALLOW,
		.source = MEDUSA_DECISION_BASELINE,
		.unavailable = MEDUSA_AUTH_SERVER_UNREACHABLE,
		.request_id = 0x1234,
		.policy_generation = 23,
		.authserver_contacted = true,
	};

	medusa_audit_apply_decision(&mad, result);

	KUNIT_EXPECT_EQ(test, MED_ALLOW, mad.ans);
	KUNIT_EXPECT_EQ(test, AS_REQUEST, (int)mad.as);
	KUNIT_EXPECT_TRUE(test, (bool)mad.decision_metadata);
	KUNIT_EXPECT_EQ(test, MEDUSA_DECISION_BASELINE,
			mad.decision_source);
	KUNIT_EXPECT_EQ(test, MEDUSA_AUTH_SERVER_UNREACHABLE,
			mad.unavailable);
	KUNIT_EXPECT_EQ(test, (u64)0x1234, mad.request_id);
	KUNIT_EXPECT_EQ(test, (u64)23, mad.policy_generation);
	KUNIT_EXPECT_STREQ(test, "baseline",
			  medusa_audit_decision_source_name(
				  mad.decision_source));
	KUNIT_EXPECT_STREQ(test, "auth_server_unreachable",
			  medusa_audit_unavailable_name(mad.unavailable));
}

static struct kunit_case audit_test_cases[] = {
	KUNIT_CASE(audit_answer_names_are_bounded),
	KUNIT_CASE(lsm_returns_preserve_stacked_denials),
	KUNIT_CASE(audit_decision_tracks_source_and_contact),
	{}
};

static struct kunit_suite audit_test_suite = {
	.name = "medusa-audit-tests",
	.test_cases = audit_test_cases,
};

kunit_test_suite(audit_test_suite);

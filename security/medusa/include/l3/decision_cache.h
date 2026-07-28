/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _MEDUSA_DECISION_CACHE_H
#define _MEDUSA_DECISION_CACHE_H

#include <linux/types.h>

#include "l3/constants.h"

struct medusa_evtype_s;

struct medusa_domain_rule_spec {
	u64 subject_domain;
	u64 object_domain;
	u64 selector;
	enum medusa_answer_t answer;
};

int medusa_decision_cache_begin(u64 generation);
int medusa_decision_cache_stage(struct medusa_evtype_s *event,
				u64 subject_domain, u64 object_domain,
				u64 selector, enum medusa_answer_t answer);
int
medusa_decision_cache_stage_rules(struct medusa_evtype_s *event,
				  const struct medusa_domain_rule_spec *rules,
				  u32 count);
int medusa_decision_cache_prepare(u64 generation);
void medusa_decision_cache_publish(u64 generation);
void medusa_decision_cache_abort(void);
void medusa_decision_cache_reset(void);
bool medusa_decision_cache_lookup(const struct medusa_evtype_s *event,
				  u64 subject_domain, u64 object_domain,
				  u64 selector,
				  enum medusa_answer_t *answer);

#endif

// SPDX-License-Identifier: GPL-2.0-only

#include <linux/err.h>
#include <linux/hash.h>
#include <linux/log2.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include <uapi/linux/medusa.h>

#include "l3/decision_cache.h"
#include "l3/kobject.h"
#include "l3/med_model.h"

#define MEDUSA_DECISION_CACHE_INITIAL_RULES 64U
#define MEDUSA_DECISION_CACHE_MAX_RULES 4096U

struct medusa_cached_rule {
	const struct medusa_evtype_s *event;
	u64 subject_domain;
	u64 object_domain;
	u64 selector;
	enum medusa_answer_t answer;
	bool occupied;
};

struct medusa_decision_table {
	struct rcu_head rcu;
	u64 generation;
	u32 capacity;
	u32 count;
	struct medusa_cached_rule rules[];
};

struct medusa_rule_builder {
	u64 generation;
	u32 capacity;
	u32 count;
	struct medusa_cached_rule *rules;
};

static DEFINE_MUTEX(decision_cache_lock);
static struct medusa_decision_table __rcu *active_table;
static struct medusa_decision_table *prepared_table;
static struct medusa_rule_builder *staging_rules;

static u64 medusa_rule_hash(const struct medusa_evtype_s *event,
			    u64 subject_domain, u64 object_domain,
			    u64 selector)
{
	u64 value = (u64)(uintptr_t)event;

	value ^= subject_domain + 0x9e3779b97f4a7c15ULL +
		 (value << 6) + (value >> 2);
	value ^= object_domain + 0x9e3779b97f4a7c15ULL +
		 (value << 6) + (value >> 2);
	value ^= selector + 0x9e3779b97f4a7c15ULL +
		 (value << 6) + (value >> 2);
	return value;
}

static bool
medusa_rule_key_equal(const struct medusa_cached_rule *rule,
		      const struct medusa_evtype_s *event,
		      u64 subject_domain, u64 object_domain, u64 selector)
{
	return rule->event == event &&
	       rule->subject_domain == subject_domain &&
	       rule->object_domain == object_domain &&
	       rule->selector == selector;
}

int medusa_decision_cache_begin(u64 generation)
{
	struct medusa_rule_builder *builder;

	if (!generation)
		return -EINVAL;
	builder = kzalloc_obj(*builder);
	if (!builder)
		return -ENOMEM;
	builder->rules = kcalloc(MEDUSA_DECISION_CACHE_INITIAL_RULES,
				 sizeof(*builder->rules), GFP_KERNEL);
	if (!builder->rules) {
		kfree(builder);
		return -ENOMEM;
	}
	builder->generation = generation;
	builder->capacity = MEDUSA_DECISION_CACHE_INITIAL_RULES;

	mutex_lock(&decision_cache_lock);
	if (staging_rules || prepared_table) {
		mutex_unlock(&decision_cache_lock);
		kfree(builder->rules);
		kfree(builder);
		return -EALREADY;
	}
	staging_rules = builder;
	mutex_unlock(&decision_cache_lock);
	return 0;
}

int
medusa_decision_cache_stage_rules(struct medusa_evtype_s *event,
				  const struct medusa_domain_rule_spec *new_rules,
				  u32 count)
{
	struct medusa_cached_rule *rules;
	u32 capacity;
	u32 index, next;
	int error = 0;

	if (!event || (!new_rules && count))
		return -EINVAL;

	mutex_lock(&decision_cache_lock);
	if (!staging_rules) {
		error = -EPERM;
		goto out;
	}
	if (count > MEDUSA_DECISION_CACHE_MAX_RULES - staging_rules->count) {
		error = -E2BIG;
		goto out;
	}
	for (next = 0; next < count; next++) {
		if (new_rules[next].answer != MED_ALLOW &&
		    new_rules[next].answer != MED_DENY) {
			error = -EINVAL;
			goto out;
		}
		for (index = 0; index < staging_rules->count; index++)
			if (medusa_rule_key_equal(&staging_rules->rules[index],
						  event,
						  new_rules[next].subject_domain,
						  new_rules[next].object_domain,
						  new_rules[next].selector)) {
				error = -EEXIST;
				goto out;
			}
		for (index = 0; index < next; index++)
			if (new_rules[index].subject_domain ==
				    new_rules[next].subject_domain &&
			    new_rules[index].object_domain ==
				    new_rules[next].object_domain &&
			    new_rules[index].selector ==
				    new_rules[next].selector) {
				error = -EEXIST;
				goto out;
			}
	}
	if (staging_rules->count + count > staging_rules->capacity) {
		capacity = roundup_pow_of_two(staging_rules->count + count);
		capacity = min(capacity, MEDUSA_DECISION_CACHE_MAX_RULES);
		rules = krealloc_array(staging_rules->rules, capacity,
				       sizeof(*rules), GFP_KERNEL);
		if (!rules) {
			error = -ENOMEM;
			goto out;
		}
		staging_rules->rules = rules;
		staging_rules->capacity = capacity;
	}
	rules = staging_rules->rules;
	for (index = 0; index < count; index++)
		rules[staging_rules->count++] = (struct medusa_cached_rule) {
			.event = event,
			.subject_domain = new_rules[index].subject_domain,
			.object_domain = new_rules[index].object_domain,
			.selector = new_rules[index].selector,
			.answer = new_rules[index].answer,
			.occupied = true,
		};
out:
	mutex_unlock(&decision_cache_lock);
	return error;
}

int medusa_decision_cache_stage(struct medusa_evtype_s *event,
				u64 subject_domain, u64 object_domain,
				u64 selector, enum medusa_answer_t answer)
{
	const struct medusa_domain_rule_spec rule = {
		.subject_domain = subject_domain,
		.object_domain = object_domain,
		.selector = selector,
		.answer = answer,
	};

	return medusa_decision_cache_stage_rules(event, &rule, 1);
}

int medusa_decision_cache_prepare(u64 generation)
{
	struct medusa_decision_table *table;
	u32 capacity;
	u32 index;
	int error = 0;

	mutex_lock(&decision_cache_lock);
	if (!staging_rules || staging_rules->generation != generation ||
	    prepared_table) {
		error = -EPERM;
		goto out;
	}
	capacity = roundup_pow_of_two(max(staging_rules->count * 2U, 2U));
	table = kvzalloc(struct_size(table, rules, capacity), GFP_KERNEL);
	if (!table) {
		error = -ENOMEM;
		goto out;
	}
	table->generation = generation;
	table->capacity = capacity;
	table->count = staging_rules->count;
	for (index = 0; index < staging_rules->count; index++) {
		struct medusa_cached_rule *source = &staging_rules->rules[index];
		u32 slot = medusa_rule_hash(source->event,
					    source->subject_domain,
					    source->object_domain,
					    source->selector) &
			   (capacity - 1);

		while (table->rules[slot].occupied)
			slot = (slot + 1) & (capacity - 1);
		table->rules[slot] = *source;
	}
	prepared_table = table;
	kfree(staging_rules->rules);
	kfree(staging_rules);
	staging_rules = NULL;
out:
	mutex_unlock(&decision_cache_lock);
	return error;
}

void medusa_decision_cache_publish(u64 generation)
{
	struct medusa_decision_table *old;

	mutex_lock(&decision_cache_lock);
	if (WARN_ON_ONCE(!prepared_table ||
			 prepared_table->generation != generation)) {
		mutex_unlock(&decision_cache_lock);
		return;
	}
	old = rcu_replace_pointer(active_table, prepared_table,
				  lockdep_is_held(&decision_cache_lock));
	prepared_table = NULL;
	mutex_unlock(&decision_cache_lock);
	if (old)
		kvfree_rcu(old, rcu);
}

void medusa_decision_cache_abort(void)
{
	mutex_lock(&decision_cache_lock);
	if (staging_rules) {
		kfree(staging_rules->rules);
		kfree(staging_rules);
		staging_rules = NULL;
	}
	kvfree(prepared_table);
	prepared_table = NULL;
	mutex_unlock(&decision_cache_lock);
}

void medusa_decision_cache_reset(void)
{
	struct medusa_decision_table *old;

	medusa_decision_cache_abort();
	mutex_lock(&decision_cache_lock);
	old = rcu_replace_pointer(active_table, NULL,
				  lockdep_is_held(&decision_cache_lock));
	mutex_unlock(&decision_cache_lock);
	if (old)
		kvfree_rcu(old, rcu);
}

static bool
medusa_decision_cache_lookup_key(const struct medusa_decision_table *table,
				 const struct medusa_evtype_s *event,
				 u64 subject_domain, u64 object_domain,
				 u64 selector, enum medusa_answer_t *answer)
{
	u32 slot = medusa_rule_hash(event, subject_domain, object_domain,
				    selector) &
		   (table->capacity - 1);
	u32 probes;

	for (probes = 0; probes < table->capacity; probes++) {
		const struct medusa_cached_rule *rule = &table->rules[slot];

		if (!rule->occupied)
			return false;
		if (medusa_rule_key_equal(rule, event, subject_domain,
					  object_domain, selector)) {
			*answer = rule->answer;
			return true;
		}
		slot = (slot + 1) & (table->capacity - 1);
	}
	return false;
}

bool medusa_decision_cache_lookup(const struct medusa_evtype_s *event,
				  u64 subject_domain, u64 object_domain,
				  u64 selector,
				  enum medusa_answer_t *answer)
{
	const struct medusa_decision_table *table;
	static const u8 wildcard_order[] = { 0, 1, 2, 4, 3, 5, 6, 7 };
	unsigned int index;
	bool found = false;

	rcu_read_lock();
	table = rcu_dereference(active_table);
	if (!table ||
	    table->generation != (u64)READ_ONCE(medusa_authserver_magic))
		goto out;

	/* Exact keys win; progressively less-specific wildcard keys follow. */
	for (index = 0; index < ARRAY_SIZE(wildcard_order); index++) {
		u8 wildcard = wildcard_order[index];
		u64 subject = wildcard & BIT(0) ?
			MEDUSA_POLICY_DOMAIN_ANY : subject_domain;
		u64 object = wildcard & BIT(1) ?
			MEDUSA_POLICY_DOMAIN_ANY : object_domain;
		u64 operation = wildcard & BIT(2) ?
			MEDUSA_POLICY_SELECTOR_ANY : selector;

		if (medusa_decision_cache_lookup_key(table, event, subject,
						     object, operation,
						     answer)) {
			found = true;
			break;
		}
	}
out:
	rcu_read_unlock();
	return found;
}

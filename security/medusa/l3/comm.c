// SPDX-License-Identifier: GPL-2.0

/* (C) 2002 Milan Pikula <www@terminus.sk> */

#include <linux/sched/signal.h>

#include "l3/arch.h"
#include "l3/registry.h"
#include "l3/server.h"

extern struct mutex registry_lock;

inline int is_authserver_reached(enum medusa_answer_t answer)
{
	return (answer != MED_ERR);
}

inline int is_supported_medusa_answer(enum medusa_answer_t answer)
{
	return (answer == MED_ALLOW || answer == MED_DENY);
}

static struct medusa_decision_result
medusa_fallback_result(struct medusa_evtype_s *evtype,
		       enum medusa_unavailable_reason unavailable,
		       bool authserver_contacted)
{
	struct medusa_decision_result result = {
		.answer = MED_ALLOW,
		.source = MEDUSA_DECISION_BASELINE,
		.unavailable = unavailable,
		.authserver_contacted = authserver_contacted,
	};

	switch (READ_ONCE(evtype->fallback_policy)) {
	case MEDUSA_FALLBACK_BASELINE_ALLOW:
		break;
	case MEDUSA_FALLBACK_BASELINE_DENY:
		result.answer = MED_DENY;
		break;
	case MEDUSA_FALLBACK_ONLINE_REQUIRED:
		result.answer = MED_DENY;
		result.source = MEDUSA_DECISION_ONLINE_REQUIRED;
		break;
	default:
		/*
		 * A corrupted policy must not become an allow. Setter validation
		 * prevents this during normal operation.
		 */
		result.answer = MED_DENY;
		result.source = MEDUSA_DECISION_INVALID_REPLY;
		break;
	}
	return result;
}

int medusa_set_fallback_policy(struct medusa_evtype_s *evtype,
			       enum medusa_fallback_policy policy)
{
	if (!evtype)
		return -EINVAL;
	if (policy < MEDUSA_FALLBACK_BASELINE_ALLOW ||
	    policy > MEDUSA_FALLBACK_ONLINE_REQUIRED)
		return -EINVAL;

	WRITE_ONCE(evtype->fallback_policy, policy);
	return 0;
}

struct medusa_decision_result
med_decide_result(struct medusa_evtype_s *evtype, void *event,
		  void *o1, void *o2)
{
	struct medusa_decision_result result;
	struct medusa_authserver_s *authserver;

	/*
	 * An installed denial is authoritative and is never weakened by the
	 * availability or answer of a userspace server.
	 */
	if (READ_ONCE(evtype->fallback_policy) ==
	    MEDUSA_FALLBACK_BASELINE_DENY)
		return medusa_fallback_result(evtype, MEDUSA_AVAILABLE, false);

	if (ARCH_CANNOT_DECIDE(evtype))
		return medusa_fallback_result(evtype,
					      MEDUSA_AUTH_SERVER_UNREACHABLE,
					      false);

	mutex_lock(&registry_lock);
#ifdef CONFIG_MEDUSA_PROFILING
	evtype->arg_kclass[0]->l2_to_l4++;
	evtype->arg_kclass[1]->l2_to_l4++;
	evtype->l2_to_l4++;
#endif
	authserver = med_get_authserver();
	if (!authserver) {
		mutex_unlock(&registry_lock);
		return medusa_fallback_result(evtype, MEDUSA_NO_AUTH_SERVER,
					      false);
	}
	mutex_unlock(&registry_lock);

	if (authserver->is_healthy && !authserver->is_healthy()) {
		med_pr_warn_ratelimited("authorization server unhealthy, using fallback for event '%s'\n",
				       evtype->name);
		med_put_authserver(authserver);
		return medusa_fallback_result(evtype,
					      MEDUSA_AUTH_SERVER_UNHEALTHY,
					      false);
	}

	((struct medusa_event_s *)event)->evtype_id = evtype;
	if (task_tgid(current) == authserver->tgid) {
		med_pr_info("med_decide for Constable for event %s(%s:%s->%s:%s)\n",
			   evtype->name,
			   evtype->arg_name[0], evtype->arg_kclass[0]->name,
			   evtype->arg_name[1], evtype->arg_kclass[1]->name);
	}
	result.authserver_contacted = false;
	result.answer = authserver->decide(event, o1, o2,
					   &result.authserver_contacted);
	result.source = MEDUSA_DECISION_AUTH_SERVER;
	result.unavailable = MEDUSA_AVAILABLE;
	if (!is_authserver_reached(result.answer)) {
		result = medusa_fallback_result(evtype,
					       MEDUSA_AUTH_SERVER_UNREACHABLE,
					       true);
	} else if (!is_supported_medusa_answer(result.answer)) {
		char *err_str = "ERROR: authserver returned not supported answer";

		/* if we received code which is not known or not supported, we
		 * want to DENY the operation since according to protocol, the
		 * authorization server should send Medusa only supported codes
		 * and if it did not, this is suspicious
		 */
		med_pr_err("%s %d for event %s(%s:%s->%s:%s)\n",
			   err_str, result.answer, evtype->name,
			   evtype->arg_name[0], evtype->arg_kclass[0]->name,
			   evtype->arg_name[1], evtype->arg_kclass[1]->name);
		result.answer = MED_DENY;
		result.source = MEDUSA_DECISION_INVALID_REPLY;
	}
#ifdef CONFIG_MEDUSA_PROFILING
	else {
		MED_LOCK_W(registry_lock);
		evtype->l4_to_l2++;
		MED_UNLOCK_W(registry_lock);
	}
#endif
	med_put_authserver(authserver);
	return result;
}

enum medusa_answer_t med_decide(struct medusa_evtype_s *evtype, void *event,
				void *o1, void *o2)
{
	return med_decide_result(evtype, event, o1, o2).answer;
}

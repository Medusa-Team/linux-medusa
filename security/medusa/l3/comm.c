/* comm.c, (C) 2002 Milan Pikula <www@terminus.sk>
 *
 */
#include <linux/medusa/l3/arch.h>
#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l3/server.h>
#include <linux/medusa/l4/interface.h>

#include "l3_internals.h"

medusa_answer_t development_converter(authserver_answer_t code)
{
	medusa_answer_t retval;
	switch(code) {
		case AUTHS_ERR:
			retval = MED_ERR;
			break;
		case AUTHS_ALLOW:
		case AUTHS_DBG_ALLOW:
		case AUTHS_FORCE_ALLOW:
		case AUTHS_NOT_REACHED:
			retval = MED_ALLOW;
			break;
		case AUTHS_DENY:
		case AUTHS_SKIP:
			retval = MED_DENY;
			break;
		default:
			retval = MED_ALLOW;
	}
	return retval;
}

medusa_answer_t production_converter(authserver_answer_t code)
{
	medusa_answer_t retval;
	switch(code) {
		case AUTHS_ERR:
			retval = MED_ERR;
			break;
		case AUTHS_ALLOW:
		case AUTHS_FORCE_ALLOW:
			retval = MED_ALLOW;
			break;
		case AUTHS_DENY:
		case AUTHS_NOT_REACHED:
		case AUTHS_SKIP:
			retval = MED_DENY;
			break;
		default:
			retval = MED_DENY;
	}
	return retval;
}

medusa_answer_t convert_to_medusa_answer(authserver_answer_t auths_code)
{
	medusa_answer_t (*code_converter)(authserver_answer_t code);
#ifdef CONFIG_MEDUSA_PROD
	code_converter = production_converter;
#else
	code_converter = development_converter;
#endif
	return code_converter(auths_code);

}

medusa_answer_t med_decide(struct medusa_evtype_s * evtype, void * event, void * o1, void * o2)
{
	struct medusa_authserver_s * authserver;
	authserver_answer_t auths_code;
	medusa_answer_t retval;

	if (ARCH_CANNOT_DECIDE(evtype))
		return MED_ALLOW;

	MED_LOCK_W(registry_lock);
#ifdef CONFIG_MEDUSA_PROFILING
	evtype->arg_kclass[0]->l2_to_l4++;
	evtype->arg_kclass[1]->l2_to_l4++;
	evtype->l2_to_l4++;
#endif
	authserver = med_get_authserver();
	if (!authserver) {
		if (evtype->arg_kclass[0]->unmonitor)
			evtype->arg_kclass[0]->unmonitor((struct medusa_kobject_s *) o1);
		if (evtype->arg_kclass[1]->unmonitor)
			evtype->arg_kclass[1]->unmonitor((struct medusa_kobject_s *) o2);
		MED_UNLOCK_W(registry_lock);
		return MED_ALLOW;
	}
	MED_UNLOCK_W(registry_lock);

	((struct medusa_event_s *)event)->evtype_id = evtype;
	auths_code = authserver->decide(event, o1, o2);
	retval = convert_to_medusa_answer(auths_code);
#ifdef CONFIG_MEDUSA_PROFILING
	if (retval != MED_ERR) {
		MED_LOCK_W(registry_lock);
		evtype->l4_to_l2++;
		MED_UNLOCK_W(registry_lock);
	}
#endif
	med_put_authserver(authserver);
	return retval;
}

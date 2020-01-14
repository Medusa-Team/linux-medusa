#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l1/ipc.h>
#include <linux/init.h>
#include <linux/mm.h>
#include "kobject_ipc.h"

struct ipc_event {
	MEDUSA_ACCESS_HEADER;
	unsigned int ipc_class;
};

MED_ATTRS(ipc_event) {
	MED_ATTR_RO (ipc_event, ipc_class, "ipc_class", MED_UNSIGNED),
	MED_ATTR_END
};

MED_EVTYPE(ipc_event, "getipc", ipc_kobject, "ipc", ipc_kobject, "ipc");

int __init ipc_evtype_init(void) {
	MED_REGISTER_EVTYPE(ipc_event, MEDUSA_EVTYPE_NOTTRIGGERED);
	return 0;
}

/*
 * This routine expects the existing, but !is_med_object_valid Medusa ipcp security struct!
 * For validity of an IPC object, it must be always called after ipc_getref(),
 * before ipc_putref() functions.
 *
 * ipc_getref() increases ipcp->refcount, co we tell to ipc_kern2kobj() function
 * to decrease it; of course not in ipcp->refcount, but in its copy in ipc_kobject
 */
int ipc_kobj_validate_ipcp(struct kern_ipc_perm *ipcp) {
	medusa_answer_t retval;
	struct ipc_event event;
	struct ipc_kobject sender;

	init_med_object(&(ipc_security(ipcp)->med_object));
	/* 3-th argument is true: decrement IPC object's refcount in returned object */
	if (unlikely(ipc_kern2kobj(&sender, ipcp, true) == NULL))
		return MED_ERR;

	memset(&event, '\0', sizeof(struct ipc_event));
	retval = MED_DECIDE(ipc_event, &event, &sender, &sender);
	if (retval != MED_ERR)
		return 1;
	return MED_ERR;
}

__initcall(ipc_evtype_init);

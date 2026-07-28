// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_socket.h"
#include "l2/audit_medusa.h"

struct socket_create_access {
	MEDUSA_ACCESS_HEADER;
	int family;
	int type;
	int protocol;
};

MED_ATTRS(socket_create_access) {
	MED_ATTR_RO(socket_create_access, family, "family", MED_UNSIGNED),
	MED_ATTR_RO(socket_create_access, type, "type", MED_UNSIGNED),
	MED_ATTR_RO(socket_create_access, protocol, "protocol", MED_UNSIGNED),
	MED_ATTR_END
};

// acctype - subject - object
MED_ACCTYPE(socket_create_access, "socket_create",
	    process_kobject, "process",
	    process_kobject, "process");

static int __init socket_create_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(socket_create_access,
			     MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

enum medusa_answer_t medusa_socket_create(int family, int type, int protocol)
{
	struct socket_create_access access;
	struct process_kobject process;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0 &&
	    !MEDUSA_FALLBACK_REQUIRES_DECISION(socket_create_access))
		return MED_ALLOW;

	if (MEDUSA_MONITORED_ACCESS_S(socket_create_access, task_security(current))) {
		process_kern2kobj(&process, current);

		access.family = family;
		access.type = type;
		access.protocol = protocol;
		return medusa_audit_decision_result(
			"socket_create",
			MED_DECIDE_RESULT(socket_create_access, &access,
					  &process, &process),
			task_security(current)->audit);
	}

	return MED_ALLOW;
}

device_initcall(socket_create_acctype_init);

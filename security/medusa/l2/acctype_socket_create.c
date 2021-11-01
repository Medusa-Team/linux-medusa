// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_socket.h"

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
MED_ACCTYPE(socket_create_access, "socket_create", process_kobject, "process", process_kobject, "process");

int __init socket_create_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(socket_create_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

enum medusa_answer_t medusa_socket_create(int family, int type, int protocol)
{
	struct socket_create_access access;
	struct process_kobject process;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) && process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (MEDUSA_MONITORED_ACCESS_S(socket_create_access, task_security(current))) {
		process_kern2kobj(&process, current);

		access.family = family;
		access.type = type;
		access.protocol = protocol;
		return MED_DECIDE(socket_create_access, &access, &process, &process);
	}

	return MED_ALLOW;
}

device_initcall(socket_create_acctype_init);

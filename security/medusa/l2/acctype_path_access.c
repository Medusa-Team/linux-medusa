#include <linux/medusa/l3/registry.h>
#include <linux/mm.h>

#include "kobject_process.h"

struct path_access {
	MEDUSA_ACCESS_HEADER;
	char action[NAME_MAX+1];
};

MED_ATTRS(path_access) {
	MED_ATTR_RO (path_access, action, "action", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(path_access, "path_access", process_kobject, "process",
		process_kobject, "process");

int __init path_acctype_init(void) {
	MED_REGISTER_ACCTYPE(path_access,
	MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

medusa_answer_t medusa_path_access(const char *action, const char *pathname, char **path_to_redirect)
{
	struct path_access access;
	struct process_kobject process;
	medusa_answer_t retval;

	if (!strncmp(pathname, "/tmp/medusa_path", strlen("/tmp/medusa_path"))) {
		if (!strcmp(pathname, "/tmp/medusa_path_deny"))
			retval = MED_DENY;
		else if (!strcmp(pathname, "/tmp/medusa_path_allow"))
			retval = MED_ALLOW;
		else if (!strcmp(pathname, "/tmp/medusa_path_fake_allow"))
			retval = MED_FAKE_ALLOW;
		else if (!strcmp(pathname, "/tmp/medusa_path_redirect")) {
			*path_to_redirect = kstrdup("/tmp/medusa_redirected", GFP_KERNEL);
			retval = MED_ALLOW;
		}

		printk("MEDUSA PATH_ACCESS: act='%s', path='%s', redir='%s', retval=%d\n", \
			action, pathname, *path_to_redirect, retval);
		return retval;
	}

        memset(&access, '\0', sizeof(struct path_access));
        /* process_kobject process is zeroed by process_kern2kobj function */

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (MEDUSA_MONITORED_ACCESS_S(path_access, task_security(current))) {
		strncpy(access.action, action, NAME_MAX);
		access.action[strlen(action)] = '\0';
		process_kern2kobj(&process, current);
		retval = MED_DECIDE(path_access, &access, &process, &process);
		return retval;
	}
	return MED_ALLOW;
}

int medusa_monitored_path(void)
{
	return MEDUSA_MONITORED_ACCESS_S(path_access, task_security(current));
}

void medusa_monitor_path(int flag)
{
	if (flag)
		MEDUSA_MONITOR_ACCESS_S(path_access, task_security(current));
	else
		MEDUSA_UNMONITOR_ACCESS_S(path_access, task_security(current));
}
__initcall(path_acctype_init);

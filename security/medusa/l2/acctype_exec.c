// SPDX-License-Identifier: GPL-2.0

#include <linux/binfmts.h>

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'exec' access type, with subj=task and obj=inode */

/* in fact, there are 2 of them. They're exactly the same, and differ
 * only in the place where they are triggered.
 */

struct exec_faccess {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX + 1];
};

struct exec_paccess {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX + 1];
};

MED_ATTRS(exec_faccess) {
	MED_ATTR_RO(exec_faccess, filename, "filename", MED_STRING),
	MED_ATTR_END
};
MED_ATTRS(exec_paccess) {
	MED_ATTR_RO(exec_paccess, filename, "filename", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(exec_faccess, "fexec",
	    process_kobject, "process",
	    file_kobject, "file");
MED_ACCTYPE(exec_paccess, "pexec",
	    process_kobject, "process",
	    file_kobject, "file");

static int __init exec_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(exec_faccess, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	MED_REGISTER_ACCTYPE(exec_paccess, MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT);
	return 0;
}

static void medusa_exec_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_d_path(ab, " path=", mad->name.dir);
	audit_log_format(ab, " filename=");
	audit_log_untrustedstring(ab, mad->name.name);
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_fexec(struct inode *inode,
					    const char *filename)
{
	struct exec_faccess access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	strncpy(access.filename, filename, sizeof(access.filename));
	access.filename[sizeof(access.filename) - 1] = '\0';

	process_kern2kobj(&process, current);
	file_kern2kobj(&file, inode);
	file_kobj_live_add(inode);
	retval = MED_DECIDE(exec_faccess, &access, &process, &file);
	file_kobj_live_remove(inode);
	if (retval != MED_ERR)
		return retval;
	return MED_ALLOW;
}

static enum medusa_answer_t medusa_do_pexec(struct inode *inode,
					    const char *filename)
{
	struct exec_paccess access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	strncpy(access.filename, filename, sizeof(access.filename));
	access.filename[sizeof(access.filename) - 1] = '\0';

	process_kern2kobj(&process, current);
	file_kern2kobj(&file, inode);
	file_kobj_live_add(inode);
	retval = MED_DECIDE(exec_paccess, &access, &process, &file);
	file_kobj_live_remove(inode);
	if (retval == MED_ERR)
		retval = MED_ALLOW;
	return retval;
}

enum medusa_answer_t medusa_exec(struct linux_binprm *bprm)
{
	struct path *path = &bprm->file->f_path;
	// TODO: Can we use file_inode?
	struct inode *inode = d_backing_inode(path->dentry);
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .ans = MED_ALLOW, .as = AS_NO_REQUEST };

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0)
		return mad.ans;

	if (!is_med_magic_valid(&(inode_security(inode)->med_object)) &&
	    file_kobj_validate_dentry_dir(path->mnt, path->dentry) <= 0)
		return mad.ans;

	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(inode))) ||
	    !vs_intersects(VSR(task_security(current)), VS(inode_security(inode)))) {
		mad.vs.srw.vst = VS(inode_security(inode));
		mad.vs.srw.vss = VSS(task_security(current));
		mad.vs.srw.vsr = VSR(task_security(current));
		mad.ans = MED_DENY;
		goto audit;
	}
	/* TODO: Two types of monitoring need to be supported by audit */
	if (MEDUSA_MONITORED_ACCESS_S(exec_paccess, task_security(current))) {
		mad.ans = medusa_do_pexec(inode, bprm->filename);
		mad.as = AS_REQUEST;
		if (mad.ans == MED_DENY)
			goto audit;
	}
	if (MEDUSA_MONITORED_ACCESS_O(exec_faccess, inode_security(inode))) {
		mad.ans = medusa_do_fexec(inode, bprm->filename);
		mad.as = AS_REQUEST;
	}
audit:
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_NONE;
		cad.u.tsk = current;
		mad.function = "exec";
		mad.name.dir = path;
		mad.name.name = bprm->filename;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_exec_pacb);
	}
	return mad.ans;
}

int medusa_monitored_pexec(void)
{
	return MEDUSA_MONITORED_ACCESS_S(exec_paccess, task_security(current));
}

void medusa_monitor_pexec(int flag)
{
	if (flag)
		MEDUSA_MONITOR_ACCESS_S(exec_paccess, task_security(current));
	else
		MEDUSA_UNMONITOR_ACCESS_S(exec_paccess, task_security(current));
}

device_initcall(exec_acctype_init);

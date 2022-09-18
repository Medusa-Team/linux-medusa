// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'rmdir' access type, with subj=task and obj=inode */

struct rmdir_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
};

MED_ATTRS(rmdir_access) {
	MED_ATTR_RO(rmdir_access, filename, "filename", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(rmdir_access, "rmdir", process_kobject, "process",
		file_kobject, "file");

int __init rmdir_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(rmdir_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_rmdir(const struct path *dir, struct dentry *dentry)
{
	struct rmdir_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	file_kobj_dentry2string_mnt(dir, dentry, access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, dentry->d_inode);
	file_kobj_live_add(dentry->d_inode);
	retval = MED_DECIDE(rmdir_access, &access, &process, &file);
	file_kobj_live_remove(dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_rmdir(const struct path *dir, struct dentry *dentry)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .vsi = VS_SW_N };

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		goto audit;

	if (!is_med_magic_valid(&(inode_security(dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry_dir(dir->mnt, dentry) <= 0)
		goto audit;
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(dentry->d_inode)))
		) {
		mad.vs.sw.vst = VS(inode_security(dentry->d_inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		retval = MED_DENY;
		goto audit;
	} else
		mad.vsi = VS_INTERSECT;
	if (MEDUSA_MONITORED_ACCESS_O(rmdir_access, inode_security(dentry->d_inode))) {
		retval = medusa_do_rmdir(dir, dentry);
		mad.event = EVENT_MONITORED;
	} else
		mad.event = EVENT_MONITORED_N;
audit:
#ifdef CONFIG_AUDIT
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_TASK;
		cad.u.tsk = current;
		mad.function = "rmdir";
		mad.med_answer = retval;
		mad.path = dir;
		mad.dentry = dentry;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_simple_file_cb);
	}
#endif
	return retval;
}

device_initcall(rmdir_acctype_init);

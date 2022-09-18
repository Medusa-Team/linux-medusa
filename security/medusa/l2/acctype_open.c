// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'open' access type, with subj=task and obj=inode */

struct open_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
};

MED_ATTRS(open_access) {
	MED_ATTR_RO(open_access, filename, "filename", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(open_access, "open", process_kobject, "process",
	file_kobject, "file");

int __init open_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(open_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_open(struct path *path, struct inode *inode)
{
	struct open_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	file_kobj_dentry2string_mnt(path, path->dentry, access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, inode);
	file_kobj_live_add(inode);
	retval = MED_DECIDE(open_access, &access, &process, &file);
	file_kobj_live_remove(inode);
	return retval;
}

enum medusa_answer_t medusa_open(struct file *file)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .vsi = VS_SW_N };

	struct path *path = &file->f_path;
	const u8 acc_mode = ACC_MODE(file->f_flags);
	// TODO: Can we use file_inode?
	struct inode *inode = d_backing_inode(path->dentry);

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0) {
		/* med_pr_info("open: can't validate subject\n"); */
		goto audit;
	}

	if (!is_med_magic_valid(&(inode_security(inode)->med_object)) &&
		file_kobj_validate_dentry_dir(path->mnt, path->dentry) <= 0) {
		/* med_pr_info("open: can't validate object\n"); */
		goto audit;
	}
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(inode))) ||
		(acc_mode & MAY_READ && !vs_intersects(VSR(task_security(current)), VS(inode_security(inode)))) ||
		(acc_mode & MAY_WRITE && !vs_intersects(VSW(task_security(current)), VS(inode_security(inode))))) {
		mad.vs.sw.vst = VS(inode_security(inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		retval = MED_DENY;
	} else
		mad.vsi = VS_INTERSECT;
	if (MEDUSA_MONITORED_ACCESS_O(open_access, inode_security(inode))) {
		/* med_pr_info("open: Constable will decide\n"); */
		mad.event = EVENT_MONITORED;
		retval = medusa_do_open(path, inode);
	} else
		mad.event = EVENT_MONITORED_N;
	/* med_pr_info("open: everything OK\n"); */
audit:
#ifdef CONFIG_AUDIT
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_TASK;
		cad.u.tsk = current;
		mad.function = "open";
		mad.med_answer = retval;
		mad.path = &file->f_path;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_path_cb);
	}
#endif
	return retval;
}

device_initcall(open_acctype_init);

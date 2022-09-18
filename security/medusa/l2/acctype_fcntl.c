// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'fcntl' access type, with subj=task and obj=inode */

struct fcntl_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	unsigned int cmd;
	unsigned long arg;
};

MED_ATTRS(fcntl_access) {
	MED_ATTR_RO(fcntl_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(fcntl_access, cmd, "cmd", MED_UNSIGNED),
	MED_ATTR_RO(fcntl_access, arg, "arg", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(fcntl_access, "fcntl", process_kobject, "process",
	file_kobject, "file");

int __init fcntl_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(fcntl_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_fcntl_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_d_path(ab, " path=", mad->path);
	audit_log_format(ab, " cmd=%d", mad->pacb.fcntl.cmd);
	audit_log_format(ab, " arg=%lu", mad->pacb.fcntl.arg);
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_fcntl(struct file *file, unsigned int cmd,
					unsigned long arg, struct inode *inode)
{
	struct fcntl_access access;
	struct process_kobject process;
	struct file_kobject kfile;
	enum medusa_answer_t retval;

	access.cmd = cmd;
	access.arg = arg;
	file_kobj_dentry2string_mnt(&file->f_path, file_dentry(file), access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&kfile, inode);
	file_kobj_live_add(inode);
	retval = MED_DECIDE(fcntl_access, &access, &process, &kfile);
	file_kobj_live_remove(inode);
	return retval;
}

enum medusa_answer_t medusa_fcntl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .vsi = VS_SW_N };

	struct inode *inode = file_inode(file);
	if (unlikely(IS_PRIVATE(inode))) {
		return MED_ALLOW;
	}

	if (cmd != F_SETLK && cmd != F_SETLKW &&
		cmd != F_SETOWN && cmd != F_SETSIG && cmd != F_SETFL) {
		return MED_ALLOW;
	}

	if (cmd == F_SETFL && !((arg ^ file->f_flags) & O_APPEND)) {
		return MED_ALLOW;
	}

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		goto audit;

	if (!is_med_magic_valid(&(inode_security(inode)->med_object)) &&
		file_kobj_validate_dentry_dir(file->f_path.mnt, file_dentry(file)) <= 0)
		goto audit;
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(inode)))
		) {
		mad.vs.sw.vst = VS(inode_security(inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		retval = MED_DENY;
	} else
		mad.vsi = VS_INTERSECT;
	/* med_pr_debug("file_fcntl: dev=%u ino=%lu vs=%*pbl act=%*pbl\n", inode->i_sb->s_dev, inode->i_ino, CONFIG_MEDUSA_VS, &VS(inode_security(inode)), CONFIG_MEDUSA_ACT, &inode_security(inode)->med_object.act); */
	if (MEDUSA_MONITORED_ACCESS_O(fcntl_access, inode_security(inode))) {
		retval = medusa_do_fcntl(file, cmd, arg, inode);
		mad.event = EVENT_MONITORED;
	} else
		mad.event = EVENT_MONITORED_N;
audit:
#ifdef CONFIG_AUDIT
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_TASK;
		cad.u.tsk = current;
		mad.function = "fcntl";
		mad.med_answer = retval;
		mad.path = &file->f_path;
		mad.pacb.fcntl.cmd = cmd;
		mad.pacb.fcntl.arg = arg;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_fcntl_pacb);
	}
#endif
	return retval;
}

device_initcall(fcntl_acctype_init);

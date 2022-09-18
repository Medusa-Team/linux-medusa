// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'chown' access type, with subj=task and obj=inode */

struct chown_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	kuid_t uid;
	kgid_t gid;
};

MED_ATTRS(chown_access) {
	MED_ATTR_RO(chown_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(chown_access, uid, "uid", MED_UNSIGNED),
	MED_ATTR_RO(chown_access, gid, "gid", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(chown_access, "chown", process_kobject, "process",
		file_kobject, "file");

int __init chown_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(chown_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_chown_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_d_path(ab, " path=", mad->path);
	audit_log_format(ab, " uid=%d", from_kuid(&init_user_ns, mad->pacb.chown.uid));
	audit_log_format(ab, " gid=%d", from_kgid(&init_user_ns, mad->pacb.chown.gid));
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	struct chown_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;

	access.uid = uid;
	access.gid = gid;
	file_kobj_dentry2string_mnt(path, path->dentry, access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, path->dentry->d_inode);
	file_kobj_live_add(path->dentry->d_inode);
	retval = MED_DECIDE(chown_access, &access, &process, &file);
	file_kobj_live_remove(path->dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
	enum medusa_answer_t retval = MED_ALLOW;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .vsi = VS_SW_N };

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		goto audit;

	if (!is_med_magic_valid(&(inode_security(path->dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry_dir(path->mnt, path->dentry) <= 0)
		goto audit;
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(path->dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(path->dentry->d_inode)))
		) {
		mad.vs.sw.vst = VS(inode_security(path->dentry->d_inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		retval = MED_DENY;
	} else
		mad.vsi = VS_INTERSECT;
	if (MEDUSA_MONITORED_ACCESS_O(chown_access, inode_security(path->dentry->d_inode))) {
		retval = medusa_do_chown(path, uid, gid);
		mad.event = EVENT_MONITORED;
	} else
		mad.event = EVENT_MONITORED_N;
audit:
#ifdef CONFIG_AUDIT
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_TASK;
		cad.u.tsk = current;
		mad.function = "chown";
		mad.med_answer = retval;
		mad.path = path;
		mad.pacb.chown.uid = uid;
		mad.pacb.chown.gid = gid;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_chown_pacb);
	}
#endif
	return retval;
}

device_initcall(chown_acctype_init);

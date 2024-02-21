// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'rename' access type, with subj=task and obj=inode */

struct rename_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX + 1];
	char newname[NAME_MAX + 1];
};

MED_ATTRS(rename_access) {
	MED_ATTR_RO(rename_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(rename_access, newname, "newname", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(rename_access, "rename", process_kobject, "process",
	    file_kobject, "file");

static int __init rename_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(rename_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_rename_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_d_path(ab, " old_dir=", mad->old_dir);

	audit_log_format(ab, " old_name=");
	spin_lock(&mad->old_dentry->d_lock);
	audit_log_untrustedstring(ab, mad->old_dentry->d_name.name);
	spin_unlock(&mad->old_dentry->d_lock);

	audit_log_d_path(ab, " new_dir=", mad->new_dir);

	audit_log_format(ab, " new_name=");
	spin_lock(&mad->new_dentry->d_lock);
	audit_log_untrustedstring(ab, mad->new_dentry->d_name.name);
	spin_unlock(&mad->new_dentry->d_lock);
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_rename(struct dentry *old_dentry, const char *newname)
{
	struct rename_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;
	int newnamelen;

	dentry2string(old_dentry, access.filename);
	newnamelen = strlen(newname);
	if (newnamelen > NAME_MAX)
		newnamelen = NAME_MAX;
	memcpy(access.newname, newname, newnamelen);
	access.newname[newnamelen] = '\0';
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, old_dentry->d_inode);
	file_kobj_live_add(old_dentry->d_inode);
	retval = MED_DECIDE(rename_access, &access, &process, &file);
	file_kobj_live_remove(old_dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_rename(const struct path *old_path,
				   struct dentry *old_dentry,
				   const struct path *new_path,
				   struct dentry *new_dentry)
{
	struct path target_upper;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .ans = MED_ALLOW, .as = AS_NO_REQUEST };

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0)
		return mad.ans;

	if (!is_med_magic_valid(&(inode_security(old_dentry->d_inode)->med_object)) &&
	    file_kobj_validate_dentry_dir(old_path->mnt, old_dentry) <= 0)
		return mad.ans;
	/* check S and W access to old_dentry */
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(old_dentry->d_inode))) ||
	    !vs_intersects(VSW(task_security(current)), VS(inode_security(old_dentry->d_inode)))) {
		mad.vs.sw.vst = VS(inode_security(old_dentry->d_inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		mad.ans = MED_DENY;
		goto audit;
	}

	medusa_get_upper_and_parent(new_path, &target_upper, NULL);
	if (!is_med_magic_valid(&(inode_security(target_upper.dentry->d_inode)->med_object)) &&
	    file_kobj_validate_dentry_dir(target_upper.mnt, target_upper.dentry) <= 0) {
		medusa_put_upper_and_parent(&target_upper, NULL);
		/* TODO: this goto statement is subjective */
		goto audit;
	}
	/* check S and W access to target_upper */
	if (!vs_intersects(VSS(task_security(current)),
			   VS(inode_security(target_upper.dentry->d_inode))) ||
	    !vs_intersects(VSW(task_security(current)),
			   VS(inode_security(target_upper.dentry->d_inode)))) {
		mad.vs.sw.vst = VS(inode_security(target_upper.dentry->d_inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		medusa_put_upper_and_parent(&target_upper, NULL);
		mad.ans = MED_DENY;
		goto audit;
	}

	if (MEDUSA_MONITORED_ACCESS_O(rename_access, inode_security(old_dentry->d_inode))) {
		mad.ans = medusa_do_rename(old_dentry, new_dentry->d_name.name);
		mad.as = AS_REQUEST;
	}
	med_magic_invalidate(&(inode_security(old_dentry->d_inode)->med_object));
audit:
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_NONE;
		cad.u.tsk = current;
		mad.function = "rename";
		mad.old_dir = old_path;
		mad.old_dentry = old_dentry;
		mad.new_dir = new_path;
		mad.new_dentry = new_dentry;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_rename_pacb);
	}
	return mad.ans;
}

device_initcall(rename_acctype_init);

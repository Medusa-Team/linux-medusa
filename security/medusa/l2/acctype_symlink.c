// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/audit_medusa.h"

/* let's define the 'symlink' access type, with subj=task and obj=inode */

struct symlink_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX + 1];
	/* hope we will fit on the stack. the string won't fit.. of course. */
	char oldname[NAME_MAX + 1];
};

MED_ATTRS(symlink_access) {
	MED_ATTR_RO(symlink_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(symlink_access, oldname, "oldname", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(symlink_access, "symlink",
	    process_kobject, "process",
	    file_kobject, "file");

static int __init symlink_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(symlink_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_symlink_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	audit_log_d_path(ab, " dir=", mad->name.dir);
	audit_log_format(ab, " name=");
	spin_lock(&mad->name.dentry->d_lock);
	audit_log_untrustedstring(ab, mad->name.dentry->d_name.name);
	spin_unlock(&mad->name.dentry->d_lock);
	audit_log_format(ab, " oldname=");
	audit_log_untrustedstring(ab, mad->name.name);
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_symlink(struct path *dir,
					      struct dentry *dentry,
					      const char *oldname)
{
	struct symlink_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;
	int oldnamelen;

	file_kobj_dentry2string_mnt(dir, dentry, access.filename);
	oldnamelen = strlen(oldname);
	if (oldnamelen > NAME_MAX)
		oldnamelen = NAME_MAX;
	memcpy(access.oldname, oldname, oldnamelen);
	access.oldname[oldnamelen] = '\0';
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, dir->dentry->d_inode);
	file_kobj_live_add(dir->dentry->d_inode);
	retval = MED_DECIDE(symlink_access, &access, &process, &file);
	file_kobj_live_remove(dir->dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_symlink(const struct path *dir,
				    struct dentry *dentry,
				    const char *oldname)
{
	struct path ndcurrent, ndupper;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .ans = MED_ALLOW, .as = AS_NO_REQUEST };

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
	    process_kobj_validate_task(current) <= 0)
		return mad.ans;

	ndcurrent = *dir;
	medusa_get_upper_and_parent(&ndcurrent, &ndupper, NULL);

	if (!is_med_magic_valid(&(inode_security(ndupper.dentry->d_inode)->med_object)) &&
	    file_kobj_validate_dentry_dir(ndupper.mnt, ndupper.dentry) <= 0) {
		medusa_put_upper_and_parent(&ndupper, NULL);
		return mad.ans;
	}
	if (!vs_intersects(VSS(task_security(current)),
			   VS(inode_security(ndupper.dentry->d_inode))) ||
	    !vs_intersects(VSW(task_security(current)),
			   VS(inode_security(ndupper.dentry->d_inode)))) {
		mad.vs.sw.vst = VS(inode_security(ndupper.dentry->d_inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		medusa_put_upper_and_parent(&ndupper, NULL);
		mad.ans = MED_DENY;
		goto audit;
	}
	if (MEDUSA_MONITORED_ACCESS_O(symlink_access, inode_security(ndupper.dentry->d_inode))) {
		mad.ans = medusa_do_symlink(&ndupper, dentry, oldname);
		mad.as = AS_REQUEST;
	}
audit:
	if (task_security(current)->audit) {
		cad.type = LSM_AUDIT_DATA_NONE;
		cad.u.tsk = current;
		mad.function = "symlink";
		mad.name.dir = dir;
		mad.name.dentry = dentry;
		mad.name.name = oldname;
		cad.medusa_audit_data = &mad;
		medusa_audit_log_callback(&cad, medusa_symlink_pacb);
	}
	medusa_put_upper_and_parent(&ndupper, NULL);
	return mad.ans;
}

device_initcall(symlink_acctype_init);

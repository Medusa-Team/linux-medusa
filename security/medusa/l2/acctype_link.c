// SPDX-License-Identifier: GPL-2.0-only

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"
#include "l2/kobject_fuck.h"
#include "l2/audit_medusa.h"

/* let's define the 'link' access type, with subj=task and obj=inode */

struct link_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	char newname[NAME_MAX+1];
};

MED_ATTRS(link_access) {
	MED_ATTR_RO(link_access, filename, "filename", MED_STRING),
	MED_ATTR_RO(link_access, newname, "newname", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(link_access, "link", process_kobject, "process",
		file_kobject, "file");

int __init link_acctype_init(void)
{
	MED_REGISTER_ACCTYPE(link_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_link_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if (mad->pacb.name) {
		audit_log_format(ab," rname=");
		audit_log_untrustedstring(ab, mad->pacb.name);
	}
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_link(struct dentry *old_dentry, const char *newname)
{
	struct link_access access;
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
	retval = MED_DECIDE(link_access, &access, &process, &file);
	file_kobj_live_remove(old_dentry->d_inode);
	return retval;
}

enum medusa_answer_t medusa_link(struct dentry *old_dentry,
				const struct path *new_dir,
				struct dentry *new_dentry)
{
	struct path ndcurrent, ndupper;
	enum medusa_answer_t retval = MED_ALLOW;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .vsi = VS_SW_N };
	int err;

	err = allow_fuck(old_dentry, new_dir, new_dentry);
	if (err < 0)
		return MED_ERR;
	else if (err == 0)
		return MED_DENY;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(inode_security(old_dentry->d_inode)->med_object)) &&
		// new_dir->mnt and old_dentry because it is a hardlink, mnt will be the same
		file_kobj_validate_dentry_dir(new_dir->mnt, old_dentry) <= 0) {
		return MED_ALLOW;
	}

	ndcurrent = *new_dir;
	medusa_get_upper_and_parent(&ndcurrent, &ndupper, NULL);

	if (!is_med_magic_valid(&(inode_security(ndupper.dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry_dir(ndupper.mnt, ndupper.dentry) <= 0) {
		medusa_put_upper_and_parent(&ndupper, NULL);
		return MED_ALLOW;
	}
	// TODO: Add VSR check for old_dentry? Rationale: UGO checks RW on target.
	// TODO: We check parecnt directory here. That could be delegated to
	// inode_permission if we choose to support that hook.
	if (!vs_intersects(VSS(task_security(current)), VS(inode_security(ndupper.dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(ndupper.dentry->d_inode))) ||
		!vs_intersects(VSS(task_security(current)), VS(inode_security(old_dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(old_dentry->d_inode)))
		) {
		mad.vs.sw.vst = VS(inode_security(old_dentry->d_inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		medusa_put_upper_and_parent(&ndupper, NULL);
		retval = MED_DENY;
		goto audit;
	} else {
		mad.vsi = VS_INTERSECT;
	}
	if (MEDUSA_MONITORED_ACCESS_O(link_access, inode_security(old_dentry->d_inode))) {
		// TODO: Is this safe to just use the name from the dentry?
		retval = medusa_do_link(old_dentry, new_dentry->d_name.name);
		mad.event = EVENT_MONITORED;
	} else {
		retval = MED_ALLOW;
		mad.event = EVENT_MONITORED_N;
	}
	medusa_put_upper_and_parent(&ndupper, NULL);
audit:
	#ifdef CONFIG_AUDIT
	cad.type = LSM_AUDIT_DATA_DENTRY;
	cad.u.dentry = old_dentry;
	mad.function = __func__;
	mad.med_answer = retval;
	mad.pacb.name = new_dentry->d_name.name;
	cad.medusa_audit_data = &mad;
	medusa_audit_log_callback(&cad, medusa_link_pacb);
	#endif
	return retval;
}

device_initcall(link_acctype_init);

#include <linux/medusa/l3/registry.h>
#include <linux/dcache.h>
#include <linux/limits.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/lsm_audit.h>
#include <linux/medusa/l2/audit_medusa.h>

#include "kobject_process.h"
#include "kobject_file.h"
#include <linux/medusa/l1/file_handlers.h>

/* let's define the 'symlink' access type, with subj=task and obj=inode */

struct symlink_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	char oldname[NAME_MAX+1]; /* hope we will fit in the stack. the string won't fit.. of course. */
};

MED_ATTRS(symlink_access) {
	MED_ATTR_RO (symlink_access, filename, "filename", MED_STRING),
	MED_ATTR_RO (symlink_access, oldname, "oldname", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(symlink_access, "symlink", process_kobject, "process",
		file_kobject, "file");

int __init symlink_acctype_init(void) {
	MED_REGISTER_ACCTYPE(symlink_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_symlink_pacb(struct audit_buffer *ab, void *pcad);
static medusa_answer_t medusa_do_symlink(struct dentry * parent, struct dentry *dentry, const char * oldname);
medusa_answer_t medusa_symlink(struct dentry *dentry, const char * oldname)
{
	struct path ndcurrent, ndupper, ndparent;
	medusa_answer_t retval = MED_ALLOW;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .event = EVENT_NONE, .vsi = VS_SW_N };

	if (!dentry || IS_ERR(dentry))
		return retval;	
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return retval;

	ndcurrent.dentry = dentry;
	ndcurrent.mnt = NULL;
	medusa_get_upper_and_parent(&ndcurrent,&ndupper,&ndparent);

	file_kobj_validate_dentry(ndparent.dentry,ndparent.mnt);

	if (!is_med_magic_valid(&(inode_security(ndparent.dentry->d_inode)->med_object)) &&
			file_kobj_validate_dentry(ndparent.dentry,ndparent.mnt) <= 0) {
		medusa_put_upper_and_parent(&ndupper, &ndparent);
		return retval;
	}
	if (!vs_intersects(VSS(task_security(current)),VS(inode_security(ndparent.dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)),VS(inode_security(ndparent.dentry->d_inode)))
	) {
		mad.vs.sw.vst = VS(inode_security(ndparent.dentry->d_inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		medusa_put_upper_and_parent(&ndupper, &ndparent);
		retval = MED_DENY;
		goto audit;
	} else {
		mad.vsi = VS_INTERSECT;
	}
	if (MEDUSA_MONITORED_ACCESS_O(symlink_access, inode_security(ndparent.dentry->d_inode))) {
		retval = medusa_do_symlink(ndparent.dentry, ndupper.dentry, oldname);
		mad.event = EVENT_MONITORED;
	} else {
		mad.event = EVENT_MONITORED_N;
	}
	medusa_put_upper_and_parent(&ndupper, &ndparent);
audit:
#ifdef CONFIG_AUDIT
	cad.type = LSM_AUDIT_DATA_DENTRY;
	cad.u.dentry = dentry;
	mad.function = __func__;
	mad.med_answer = retval;
	mad.pacb.filename = oldname;
	cad.medusa_audit_data = &mad;
	medusa_audit_log_callback(&cad, medusa_symlink_pacb);
#endif
	return retval;
}

static void medusa_symlink_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if (mad->pacb.filename) {
		audit_log_format(ab," path=");
		audit_log_untrustedstring(ab,mad->pacb.filename);
	}
}
/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static medusa_answer_t medusa_do_symlink(struct dentry * parent, struct dentry *dentry, const char * oldname)
{
	struct symlink_access access;
	struct process_kobject process;
	struct file_kobject file;
	medusa_answer_t retval;
        int oldnamelen;

        memset(&access, '\0', sizeof(struct symlink_access));
        /* process_kobject process is zeroed by process_kern2kobj function */
        /* file_kobject file is zeroed by file_kern2kobj function */

	file_kobj_dentry2string(dentry, access.filename);
        oldnamelen = strlen(oldname);
        if (oldnamelen > NAME_MAX)
                oldnamelen = NAME_MAX;
	memcpy(access.oldname, oldname, oldnamelen);
	access.oldname[oldnamelen] = '\0';
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, parent->d_inode);
	file_kobj_live_add(parent->d_inode);
	retval = MED_DECIDE(symlink_access, &access, &process, &file);
	file_kobj_live_remove(parent->d_inode);
	if (retval != MED_ERR)
		return retval;
	return MED_ALLOW;
}
__initcall(symlink_acctype_init);

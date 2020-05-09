#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/lsm_audit.h>
#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l2/audit_medusa.h>
#include <linux/medusa/l3/med_model.h>

#include "kobject_process.h"
#include "kobject_file.h"
#include <linux/medusa/l1/file_handlers.h>

/* let's define the 'permission' access type, with subj=task and obj=inode */

struct permission_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	int mask;
};

MED_ATTRS(permission_access) {
	MED_ATTR_RO (permission_access, filename, "filename", MED_STRING),
	MED_ATTR_RO (permission_access, mask, "mask", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(permission_access, "permission", process_kobject, "process",
		file_kobject, "file");

int __init permission_acctype_init(void) {
	MED_REGISTER_ACCTYPE(permission_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_permission_pacb(struct audit_buffer *ab, void *pcad);
medusa_answer_t medusa_do_permission(struct dentry * dentry, struct inode * inode, int mask);
/**
 * medusa_permission - L1-called code to create access of type 'permission'.
 * @inode: input inode for permission() call
 * @mask: mask of access rights to validate
 *
 */
medusa_answer_t medusa_permission(struct inode *inode, int mask)
{
	medusa_answer_t retval = MED_ALLOW;
	struct dentry * dentry;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .event = EVENT_NONE, .vsi = VS_SRW_N };

	dentry = d_find_alias(inode);

	if (!dentry || IS_ERR(dentry))
		return retval;
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return retval;
	if (!is_med_magic_valid(&(inode_security(inode)->med_object)) &&
			file_kobj_validate_dentry(dentry,NULL) <= 0)
		return retval;
	if (
		!vs_intersects(VSS(task_security(current)),VS(inode_security(inode))) ||
		( (mask & (S_IRUGO | S_IXUGO)) &&
		  	!vs_intersects(VSR(task_security(current)),VS(inode_security(inode))) ) ||
		( (mask & S_IWUGO) &&
		  	!vs_intersects(VSW(task_security(current)),VS(inode_security(inode))) )
	   ) {
		mad.vs.srw.vst = VS(inode_security(inode));
		mad.vs.srw.vss = VSS(task_security(current));
		mad.vs.srw.vsr = VSR(task_security(current));
		mad.vs.srw.vsw = VSW(task_security(current));
		retval = MED_DENY;
		goto audit;
	} else {
		mad.vsi = VS_INTERSECT;
	}
	if (MEDUSA_MONITORED_ACCESS_O(permission_access, inode_security(inode))) {
		retval = medusa_do_permission(dentry, inode, mask);
		mad.event = EVENT_MONITORED;
	} else {
		mad.event = EVENT_MONITORED_N;
	}
audit:
#ifdef CONFIG_AUDIT
	cad.type = LSM_AUDIT_DATA_DENTRY;
	cad.u.dentry = dentry;
	mad.function = __func__;
	mad.med_answer = retval;
	mad.pacb.mode = mask;
	cad.medusa_audit_data = &mad;
	medusa_audit_log_callback(&cad, medusa_permission_pacb);
#endif
	dput(dentry);
	return retval;
}

static void medusa_permission_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if (mad->pacb.mode) {
		audit_log_format(ab," mask=%d",mad->pacb.mode);
	}
}

medusa_answer_t medusa_do_permission(struct dentry * dentry, struct inode * inode, int mask)
{
	struct permission_access access;
	struct process_kobject process;
	struct file_kobject file;
	medusa_answer_t retval;

        memset(&access, '\0', sizeof(struct permission_access));
        /* process_kobject process is zeroed by process_kern2kobj function */
        /* file_kobject file is zeroed by file_kern2kobj function */

	file_kobj_dentry2string(dentry, access.filename);
	access.mask = mask;
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, inode);
	file_kobj_live_add(inode);
	retval = MED_DECIDE(permission_access, &access, &process, &file);
	file_kobj_live_remove(inode);
	return retval;
}
__initcall(permission_acctype_init);

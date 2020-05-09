#include <linux/medusa/l3/registry.h>
#include <linux/dcache.h>
#include <linux/limits.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/lsm_audit.h>
#include <linux/medusa/l2/audit_medusa.h>

#include "kobject_process.h"
#include "kobject_file.h"
#include "kobject_fuck.h"
#include <linux/medusa/l1/file_handlers.h>

/* let's define the 'rmdir' access type, with subj=task and obj=inode */
int medusa_l1_inode_alloc_security(struct inode *inode);

struct rmdir_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
};

MED_ATTRS(rmdir_access) {
	MED_ATTR_RO (rmdir_access, filename, "filename", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(rmdir_access, "rmdir", process_kobject, "process",
		file_kobject, "file");

int __init rmdir_acctype_init(void) {
	MED_REGISTER_ACCTYPE(rmdir_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_rmdir_pacb(struct audit_buffer *ab, void *pcad);
static medusa_answer_t medusa_do_rmdir(struct dentry *dentry);
medusa_answer_t medusa_rmdir(const struct path *dir, struct dentry *dentry)
{
	medusa_answer_t retval = MED_ALLOW;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .event = EVENT_NONE, .vsi = VS_SW_N };

	if (!dentry || IS_ERR(dir->dentry) || dentry->d_inode == NULL)
		return retval;
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return retval;
	if (!is_med_magic_valid(&(inode_security(dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry(dentry,NULL) <= 0)
		return retval;
	if (!vs_intersects(VSS(task_security(current)),VS(inode_security(dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)),VS(inode_security(dentry->d_inode)))
	) {
		mad.vs.sw.vst = VS(inode_security(dentry->d_inode));
		mad.vs.sw.vss = VSS(task_security(current));
		mad.vs.sw.vsw = VSW(task_security(current));
		retval = MED_DENY;
		goto audit;
	} else {
		mad.vsi = VS_INTERSECT;
	}
	if (MEDUSA_MONITORED_ACCESS_O(rmdir_access, inode_security(dentry->d_inode))) {
		retval = medusa_do_rmdir(dentry);
		mad.event = EVENT_MONITORED;
	} else {
		mad.event = EVENT_MONITORED_N;
	}
audit:
#ifdef CONFIG_AUDIT
	cad.type = LSM_AUDIT_DATA_PATH;
	cad.u.path = *dir;
	mad.function = __func__;
	mad.med_answer = retval;
	file_kobj_dentry2string(dentry, mad.pacb.filename);
	cad.medusa_audit_data = &mad;
	medusa_audit_log_callback(&cad, medusa_rmdir_pacb);
#endif
	return retval;
}

static void medusa_rmdir_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if (mad->pacb.filename) {
		audit_log_format(ab," filename=");
		audit_log_untrustedstring(ab,mad->pacb.filename);
	}
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static medusa_answer_t medusa_do_rmdir(struct dentry *dentry)
{
	struct rmdir_access access;
	struct process_kobject process;
	struct file_kobject file;
	medusa_answer_t retval;

        memset(&access, '\0', sizeof(struct rmdir_access));
        /* process_kobject process is zeroed by process_kern2kobj function */
        /* file_kobject file is zeroed by file_kern2kobj function */

	file_kobj_dentry2string(dentry, access.filename);
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, dentry->d_inode);
	file_kobj_live_add(dentry->d_inode);
	retval = MED_DECIDE(rmdir_access, &access, &process, &file);
	file_kobj_live_remove(dentry->d_inode);
	if (retval != MED_ERR)
		return retval;
	return MED_ALLOW;
}
__initcall(rmdir_acctype_init);

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

/* let's define the 'mknod' access type, with subj=task and obj=inode */

struct mknod_access {	
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	dev_t dev;
	int mode;
};

MED_ATTRS(mknod_access) {
	MED_ATTR_RO (mknod_access, filename, "filename", MED_STRING),
	MED_ATTR_RO (mknod_access, dev, "dev", MED_UNSIGNED),
	MED_ATTR_RO (mknod_access, mode, "mode", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(mknod_access, "mknod", process_kobject, "process",
			file_kobject, "file");

int __init mknod_acctype_init(void) {
	MED_REGISTER_ACCTYPE(mknod_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_mknod_pacb(struct audit_buffer *ab, void *pcad);
static medusa_answer_t medusa_do_mknod(struct dentry *parent, struct dentry *dentry, dev_t dev, int mode);
medusa_answer_t medusa_mknod(struct dentry *dentry, dev_t dev, int mode)
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
	if (MEDUSA_MONITORED_ACCESS_O(mknod_access, inode_security(ndparent.dentry->d_inode))) {
		retval = medusa_do_mknod(ndparent.dentry, ndupper.dentry, dev, mode);
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
	mad.pacb.mknod.dev = dev;
	mad.pacb.mknod.mode = mode;
	cad.medusa_audit_data = &mad;
	medusa_audit_log_callback(&cad, medusa_mknod_pacb);
#endif
	return retval;
}

static void medusa_mknod_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if ((&(mad->pacb.mknod))->mode) {
		audit_log_format(ab," mode=%d",(&(mad->pacb.mknod))->mode);
	}
	if ((&(mad->pacb.mknod))->dev) {
		audit_log_format(ab," dev_num=%u",(&(mad->pacb.mknod))->dev);
	}
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static medusa_answer_t medusa_do_mknod(struct dentry *parent, struct dentry *dentry, dev_t dev, int mode)
{
	struct mknod_access access;
	struct process_kobject process;
	struct file_kobject file;
	medusa_answer_t retval;

        memset(&access, '\0', sizeof(struct mknod_access));
        /* process_kobject process is zeroed by process_kern2kobj function */
        /* file_kobject file is zeroed by file_kern2kobj function */

	file_kobj_dentry2string(dentry, access.filename);
	access.dev = dev;
	access.mode = mode;
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, parent->d_inode);
	file_kobj_live_add(parent->d_inode);
	retval = MED_DECIDE(mknod_access, &access, &process, &file);
	file_kobj_live_remove(parent->d_inode);
	if (retval != MED_ERR)
		return retval;
	return MED_ALLOW;
}
__initcall(mknod_acctype_init);

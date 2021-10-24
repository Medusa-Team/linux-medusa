#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* let's define the 'rename' access type, with subj=task and obj=inode */

struct rename_access {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	char newname[NAME_MAX+1];
};

MED_ATTRS(rename_access) {
	MED_ATTR_RO (rename_access, filename, "filename", MED_STRING),
	MED_ATTR_RO (rename_access, newname, "newname", MED_STRING),
	MED_ATTR_END
};

MED_ACCTYPE(rename_access, "rename", process_kobject, "process",
		file_kobject, "file");

int __init rename_acctype_init(void) {
	MED_REGISTER_ACCTYPE(rename_access, MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static enum medusa_answer_t medusa_do_rename(struct dentry *dentry, const char * newname);
enum medusa_answer_t medusa_rename(struct dentry *dentry, const char * newname)
{
	enum medusa_answer_t r;

	if (!dentry || IS_ERR(dentry) || dentry->d_inode == NULL)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(inode_security(dentry->d_inode)->med_object)) &&
			file_kobj_validate_dentry(dentry,NULL) <= 0) {
		return MED_ALLOW;
	}
	if (!vs_intersects(VSS(task_security(current)),VS(inode_security(dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)),VS(inode_security(dentry->d_inode)))
	)
		return MED_DENY;
#warning FIXME - add target directory checking
	r = MED_ALLOW;
	if (MEDUSA_MONITORED_ACCESS_O(rename_access, inode_security(dentry->d_inode)))
		r=medusa_do_rename(dentry,newname);
	med_magic_invalidate(&(inode_security(dentry->d_inode)->med_object));
	return r;
}

/* XXX Don't try to inline this. GCC tries to be too smart about stack. */
static enum medusa_answer_t medusa_do_rename(struct dentry *dentry, const char * newname)
{
	struct rename_access access;
	struct process_kobject process;
	struct file_kobject file;
	enum medusa_answer_t retval;
        int newnamelen;

        memset(&access, '\0', sizeof(struct rename_access));
        /* process_kobject process is zeroed by process_kern2kobj function */
        /* file_kobject file is zeroed by file_kern2kobj function */

	file_kobj_dentry2string(dentry, access.filename);
        newnamelen = strlen(newname);
        if (newnamelen > NAME_MAX)
                newnamelen = NAME_MAX;
	memcpy(access.newname, newname, newnamelen);
	access.newname[newnamelen] = '\0';
	process_kern2kobj(&process, current);
	file_kern2kobj(&file, dentry->d_inode);
	file_kobj_live_add(dentry->d_inode);
	retval = MED_DECIDE(rename_access, &access, &process, &file);
	file_kobj_live_remove(dentry->d_inode);
	return retval;
}
__initcall(rename_acctype_init);

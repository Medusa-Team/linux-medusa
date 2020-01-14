/* this file is not really a part of the model. however, someone may find
 * it useful.
 */

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l3/med_model.h>
#include <linux/init.h>

#include "kobject_process.h"
#include "kobject_file.h"
#include <linux/medusa/l1/file_handlers.h>

/**
 * medusa_read - L1-called code to check VS
 * @file: file to read
 *
 */
medusa_answer_t medusa_read(struct file * file)
{
	struct dentry * dentry;

	dentry = file->f_path.dentry;
	if (!dentry || IS_ERR(dentry))
		return MED_OK;
	if (!is_med_object_valid(task_security(current).med_object) &&
		process_kobj_validate_task(current) <= 0)
		return MED_OK;

	if (!is_med_object_valid(inode_security(dentry->d_inode).med_object) &&
			file_kobj_validate_dentry(dentry,NULL) <= 0)
		return MED_OK;
	if (
		!vs_intersects(VSS(&task_security(current)),VS(&inode_security(dentry->d_inode))) ||
		!vs_intersects(VSR(&task_security(current)),VS(&inode_security(dentry->d_inode)))
	   ) {
		return MED_NO;
	}

	return MED_OK;
}

/**
 * medusa_write - L1-called code to check VS
 * @file: file to write
 *
 */
medusa_answer_t medusa_write(struct file * file)
{
	struct dentry * dentry;

	dentry = file->f_path.dentry;
	if (!dentry || IS_ERR(dentry))
		return MED_OK;
	if (!is_med_object_valid(task_security(current).med_object) &&
		process_kobj_validate_task(current) <= 0)
		return MED_OK;

	if (!is_med_object_valid(inode_security(dentry->d_inode).med_object) &&
			file_kobj_validate_dentry(dentry,NULL) <= 0)
		return MED_OK;
	if (
		!vs_intersects(VSS(&task_security(current)),VS(&inode_security(dentry->d_inode))) ||
		!vs_intersects(VSW(&task_security(current)),VS(&inode_security(dentry->d_inode)))
	   ) {
		return MED_NO;
	}

	return MED_OK;
}


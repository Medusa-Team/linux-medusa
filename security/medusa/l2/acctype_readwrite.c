// SPDX-License-Identifier: GPL-2.0-only

/* this file is not really a part of the model. however, someone may find
 * it useful.
 */

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/**
 * medusa_read - L1-called code to check VS
 * @file: file to read
 *
 */
enum medusa_answer_t medusa_read(struct file *file)
{
	struct dentry *dentry;

	dentry = file->f_path.dentry;
	if (!dentry || IS_ERR(dentry))
		return MED_ALLOW;
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(inode_security(dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry(dentry, NULL, NULL) <= 0)
		return MED_ALLOW;
	if (
		!vs_intersects(VSS(task_security(current)), VS(inode_security(dentry->d_inode))) ||
		!vs_intersects(VSR(task_security(current)), VS(inode_security(dentry->d_inode)))
	   ) {
		return MED_DENY;
	}

	return MED_ALLOW;
}

/**
 * medusa_write - L1-called code to check VS
 * @file: file to write
 *
 */
enum medusa_answer_t medusa_write(struct file *file)
{
	struct dentry *dentry;

	dentry = file->f_path.dentry;
	if (!dentry || IS_ERR(dentry))
		return MED_ALLOW;
	if (!is_med_magic_valid(&(task_security(current)->med_object)) &&
		process_kobj_validate_task(current) <= 0)
		return MED_ALLOW;

	if (!is_med_magic_valid(&(inode_security(dentry->d_inode)->med_object)) &&
		file_kobj_validate_dentry(dentry, NULL, NULL) <= 0)
		return MED_ALLOW;
	if (
		!vs_intersects(VSS(task_security(current)), VS(inode_security(dentry->d_inode))) ||
		!vs_intersects(VSW(task_security(current)), VS(inode_security(dentry->d_inode)))
	   ) {
		return MED_DENY;
	}

	return MED_ALLOW;
}


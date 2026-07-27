/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_KOBJECT_PATH_GUARD_H
#define _MEDUSA_KOBJECT_PATH_GUARD_H

#include "l3/kobject.h"
#include "l1/inode.h"
#include "l1/path_guard.h"

struct path_guard_kobject {
	char path[PATH_MAX];    /* primary key in 'fetch' operation */
	unsigned long ino;      /* primary key in 'update' operation */
	unsigned int dev;       /* primary key in 'update' operation */
	char action[20];        /* type of operation 'update' ('append' or 'remove') */
	struct medusa_object_s med_object;
};

extern MED_DECLARE_KCLASSOF(path_guard_kobject);

bool path_guard_is_ready(void);
bool path_guard_path_is_allowed(const char *path,
				struct medusa_l1_inode_s *context);
bool path_guard_path_add(const char *path,
			 struct medusa_l1_inode_s *context);
bool path_guard_path_remove(const char *path,
			    struct medusa_l1_inode_s *context);

int path_guard_check(struct dentry *dentry, const struct path *path,
		     struct dentry *new);

#endif /* _MEDUSA_KOBJECT_PATH_GUARD_H */

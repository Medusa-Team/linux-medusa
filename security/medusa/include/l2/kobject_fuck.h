/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _FUCK_KOBJECT_H
#define _FUCK_KOBJECT_H

#include "l3/kobject.h"
#include "l1/inode.h"
#include "l1/fuck.h"

struct fuck_kobject {
	char path[PATH_MAX];    /* primary key in 'fetch' operation */
	unsigned long ino;      /* primary key in 'update' operation */
	unsigned int dev;       /* primary key in 'update' operation */
	char action[20];        /* type of operation 'update' ('append' or 'remove') */
	struct medusa_object_s med_object;
};
extern MED_DECLARE_KCLASSOF(fuck_kobject);

/* prototypes of L2 fuck related handlers called from L2 hooks */

int allow_fuck(struct dentry *dentry, const struct path *path, struct dentry *new);

#endif

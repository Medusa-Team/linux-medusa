#ifndef _MEDUSAFS_H
#define _MEDUSAFS_H

#include <linux/security.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/medusa/l1/medusafs.h>
#include <linux/medusa/l3/registry.h>

#define MEDUSA_VERSION_NUMBER "1.0.0"


extern struct dentry *medusafs_root_dir;

extern struct medusa_evtype_s *medusafs_evtypes;

extern void medusafs_register_evtype(char *name);


#endif

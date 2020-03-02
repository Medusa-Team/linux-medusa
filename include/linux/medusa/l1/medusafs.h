#ifndef _MEDUSAFS_H
#define _MEDUSAFS_H

#include <linux/security.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/medusa/l1/medusafs.h>



extern struct dentry *medusafs_root_dir;

extern void medusafs_register_evtype(char *name);


#endif

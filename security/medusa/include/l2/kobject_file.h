/* SPDX-License-Identifier: GPL-2.0 */

/* (C) 2002 Milan Pikula
 *
 * FILE kobject: this file defines the kobject structure for inode, e.g.
 * the data, which we want to pass to the authorization server.
 *
 * The structure contains some data from ordinary struct inode,
 * and some data from medusa_l1_inode_s, which is defined in
 * medusa/l1/inode.h.
 *
 * This file (as well as many others) is based on Medusa DS9, version
 * 0.9.2, which is (C) Marek Zelem, Martin Ockajak and myself.
 */

#ifndef _FILE_KOBJECT_H
#define _FILE_KOBJECT_H

#include <linux/capability.h>
#include "l3/kobject.h"
#include "l1/inode.h"

struct file_kobject { /* was: m_inode_inf */
/*
 * As a preparation for the total deletion of device numbers,
 * we introduce a type unsigned long to hold them. No information about
 * this type is known outside of this include file.
 *
 * ... for more folklore read the comment in kdev_t.h ;)
 */
	unsigned long dev;
	unsigned long ino;

	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	unsigned long rdev;

	struct medusa_object_s med_object;

	__u32 user;
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
	kernel_cap_t icap;	/* support for Linux capabilities */
	kernel_cap_t pcap;
	kernel_cap_t ecap;
#endif /* CONFIG_MEDUSA_FILE_CAPABILITIES */
};
extern MED_DECLARE_KCLASSOF(file_kobject);

/* the conversion routine */
int file_kern2kobj(struct file_kobject *fk, struct inode *inode);

/* we want to keep a cache of "live" inodes - the ones which participate
 * on some access right now
 */
void file_kobj_live_add(struct inode *ino);
void file_kobj_live_remove(struct inode *ino);

/* conversion beteween filename (stored in dentry) and static buffer */
void file_kobj_dentry2string(struct dentry *dentry, char *buf);
void file_kobj_dentry2string_mnt(const struct path *dir, struct dentry *dentry, char *buf);
void file_kobj_dentry2string_dir(struct path *dir, struct dentry *dentry, char *buf);
void dentry2string(struct dentry *dentry, char *buf);

#endif

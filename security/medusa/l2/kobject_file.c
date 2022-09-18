// SPDX-License-Identifier: GPL-2.0

/* (C) 2002 Milan Pikula */
#include <linux/namei.h>

#include "l2/kobject_file.h"
#include "l3/registry.h"

static inline int file_kobj2kern(struct file_kobject *fk, struct inode *inode)
{
	if (unlikely(!fk || !inode_security(inode))) {
		med_pr_err("ERROR: NULL pointer: %s: file_kobj=%p or inode_security=%p",
			__func__, fk, inode_security(inode));
		return -EINVAL;
	}

	/* TODO: either update the i-node on disk, or don't allow this at all */
	inode->i_mode = fk->mode;
	inode->i_uid = fk->uid;
	inode->i_gid = fk->gid;
	inode_security(inode)->med_object = fk->med_object;
	inode_security(inode)->user = fk->user;
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
	inode_security(inode)->ecap = fk->ecap;
	inode_security(inode)->icap = fk->icap;
	inode_security(inode)->pcap = fk->pcap;
#endif /* CONFIG_MEDUSA_FILE_CAPABILITIES */
	med_magic_validate(&(inode_security(inode)->med_object));
	return 0;
}

/*
 * This routine expects the existing Medusa inode security struct!
 */
inline int file_kern2kobj(struct file_kobject *fk, struct inode *inode)
{
	if (unlikely(!fk || !inode_security(inode))) {
		med_pr_err("ERROR: NULL pointer: %s: file_kobj=%p or inode_security=%p",
			__func__, fk, inode_security(inode));
		return -EINVAL;
	}

	memset(fk, '\0', sizeof(struct file_kobject));

	fk->dev = (inode->i_sb->s_dev);
	fk->ino = inode->i_ino;
	fk->mode = inode->i_mode;
	fk->nlink = inode->i_nlink;
	fk->uid = inode->i_uid;
	fk->gid = inode->i_gid;
	fk->rdev = (inode->i_rdev);
	fk->med_object = inode_security(inode)->med_object;
	fk->user = inode_security(inode)->user;
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
	fk->ecap = inode_security(inode)->ecap;
	fk->icap = inode_security(inode)->icap;
	fk->pcap = inode_security(inode)->pcap;
#endif /* CONFIG_MEDUSA_FILE_CAPABILITIES */
	return 0;
}

/* second, we will describe its attributes, and provide fetch and update
 * routines (that's for l4, they will be working with those descriptions)
 */

MED_ATTRS(file_kobject) {
	MED_ATTR_KEY_RO(file_kobject, dev, "dev", MED_UNSIGNED),
	MED_ATTR_KEY_RO(file_kobject, ino, "ino", MED_UNSIGNED),
	MED_ATTR(file_kobject, mode, "mode", MED_UNSIGNED),
	MED_ATTR_RO(file_kobject, nlink, "nlink", MED_UNSIGNED),
	MED_ATTR(file_kobject, uid, "uid", MED_UNSIGNED),
	MED_ATTR(file_kobject, gid, "gid", MED_UNSIGNED),
	MED_ATTR_RO(file_kobject, rdev, "rdev", MED_UNSIGNED),
	MED_ATTR_OBJECT(file_kobject),
	MED_ATTR(file_kobject, user, "user", MED_UNSIGNED),
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
	MED_ATTR(file_kobject, ecap, "ecap", MED_BITMAP | MED_LE),
	MED_ATTR(file_kobject, icap, "icap", MED_BITMAP | MED_LE),
	MED_ATTR(file_kobject, pcap, "pcap", MED_BITMAP | MED_LE),
#endif
	MED_ATTR_END
};

/* here are the inodes, which are currently being examined by the L4
 * code. This simplifies a lookup, and at the moment it is also the only
 * way for L4 to fetch or update a i-node.
 */
static DEFINE_RWLOCK(live_lock);
static struct inode *live_inodes;

/* TODO: if it shows there are many concurrent inodes in the list,
 * rewrite this to use in-kernel hashes; if there will be a FAST global
 * lookup routine, maybe we can delete this at all.
 *
 * Note that we don't modify inode ref_count: call this only with
 * locked i-node.
 */
void file_kobj_live_add(struct inode *ino)
{
	struct inode *tmp;

	write_lock(&live_lock);
	for (tmp = live_inodes; tmp; tmp = inode_security(tmp)->next_live)
		if (tmp == ino) {
			inode_security(tmp)->use_count++;
			write_unlock(&live_lock);
			return;
		}
	inode_security(ino)->next_live = live_inodes;
	inode_security(ino)->use_count = 1;
	live_inodes = ino;
	write_unlock(&live_lock);
}
void file_kobj_live_remove(struct inode *ino)
{
	struct inode *tmp;

	write_lock(&live_lock);
	if (--inode_security(ino)->use_count)
		goto out;
	if (ino == live_inodes) {
		live_inodes = inode_security(ino)->next_live;
		write_unlock(&live_lock);
		return;
	}
	for (tmp = live_inodes; inode_security(tmp)->next_live; tmp = inode_security(tmp)->next_live)
		if (inode_security(tmp)->next_live == ino) {
			inode_security(tmp)->next_live = inode_security(ino)->next_live;
			break;
		}
out:
	write_unlock(&live_lock);
}

/* Uses follow_up */
void file_kobj_dentry2string_dir(struct path *dir, struct dentry *dentry, char *buf)
{
	int len;

	if( IS_ROOT(dentry) )
	{
		struct path ndcurrent;
		ndcurrent.dentry = dentry;
		ndcurrent.mnt = dir->mnt;

		path_get(&ndcurrent);
		follow_up(&ndcurrent);
		dentry=dget(ndcurrent.dentry);
		path_put(&ndcurrent);
	}
	else
		dget(dentry);

	if (!dentry || IS_ERR(dentry) || !dentry->d_name.name) {
		buf[0] = '\0';
		dput(dentry);
		return;
	}
	len = dentry->d_name.len < NAME_MAX ?
		dentry->d_name.len : NAME_MAX;
	memcpy(buf, dentry->d_name.name, len);
	buf[len] = '\0';
	dput(dentry);
}

/* Just get the name of `dentry` into `buf`. */
void dentry2string(struct dentry *dentry, char *buf)
{
	int len;

	// TODO: This check is probably unneeded
	/* if (!dentry || IS_ERR(dentry) || !dentry->d_name.name) { */
	/* 	buf[0] = '\0'; */
	/* 	dput(dentry); */
	/* 	return; */
	/* } */
	len = dentry->d_name.len < NAME_MAX ?
		dentry->d_name.len : NAME_MAX;
	memcpy(buf, dentry->d_name.name, len);
	buf[len] = '\0';
}

/* Uses mnt from dir and then gets ndupper as original file_kobj_dentry2string() */
void file_kobj_dentry2string_mnt(const struct path *dir, struct dentry *dentry, char *buf)
{
	int len;

	if( IS_ROOT(dentry) )
	{
		struct path ndcurrent, ndupper;

		ndcurrent.dentry = dentry;
		ndcurrent.mnt = dir->mnt;
		medusa_get_upper_and_parent(&ndcurrent,&ndupper,NULL);
		dentry=dget(ndupper.dentry);
		medusa_put_upper_and_parent(&ndupper, NULL);
	}
	else
		dget(dentry);

	if (!dentry || IS_ERR(dentry) || !dentry->d_name.name) {
		buf[0] = '\0';
		dput(dentry);
		return;
	}
	len = dentry->d_name.len < NAME_MAX ?
		dentry->d_name.len : NAME_MAX;
	memcpy(buf, dentry->d_name.name, len);
	buf[len] = '\0';
	dput(dentry);
}
void file_kobj_dentry2string(struct dentry *dentry, char *buf)
{
	int len;

	if (IS_ROOT(dentry)) {
		struct path ndcurrent, ndupper;

		ndcurrent.dentry = dentry;
		ndcurrent.mnt = NULL;
		medusa_get_upper_and_parent(&ndcurrent, &ndupper, NULL);
		dentry = dget(ndupper.dentry);
		medusa_put_upper_and_parent(&ndupper, NULL);
	} else
		dget(dentry);

	if (!dentry || IS_ERR(dentry) || !dentry->d_name.name) {
		buf[0] = '\0';
		dput(dentry);
		return;
	}
	len = dentry->d_name.len < NAME_MAX ?
		dentry->d_name.len : NAME_MAX;
	memcpy(buf, dentry->d_name.name, len);
	buf[len] = '\0';
	dput(dentry);
}

// static struct file_kobject storage;

static inline struct inode *__lookup_inode_by_key(struct file_kobject *key_obj)
{
	struct inode *p;

	read_lock(&live_lock);
	for (p = live_inodes; p; p = inode_security(p)->next_live)
		if (p->i_ino == key_obj->ino)
			if (p->i_sb->s_dev == key_obj->dev)
				break;

	return p;
}

static inline void __unlookup(void)
{
	read_unlock(&live_lock);
}

static struct medusa_kobject_s *file_fetch(struct medusa_kobject_s *kobj)
{
	struct inode *p;
	struct medusa_kobject_s *retval = NULL;

	p = __lookup_inode_by_key((struct file_kobject *)kobj);
	if (!p)
		goto out_err_fetch;

	retval = kobj;
	if (unlikely(file_kern2kobj((struct file_kobject *)kobj, p) < 0))
		retval = NULL;

out_err_fetch:
	__unlookup();
	return retval;
}

static void file_unmonitor(struct medusa_kobject_s *kobj)
{
	struct inode *p;

	p = __lookup_inode_by_key((struct file_kobject *)kobj);
	if (p) {
		unmonitor_med_object(&(inode_security(p)->med_object));
		med_magic_validate(&(inode_security(p)->med_object));
	}
	__unlookup();
}

static enum medusa_answer_t file_update(struct medusa_kobject_s *kobj)
{
	struct inode *p;
	enum medusa_answer_t retval = MED_ERR;

	p = __lookup_inode_by_key((struct file_kobject *)kobj);
	if (!p)
		goto out_err_update;

	retval = MED_ALLOW;
	if (unlikely(file_kobj2kern((struct file_kobject *)kobj, p) < 0))
		retval = MED_ERR;
	/* med_pr_info("file_update: dev=%lu ino=%lu vs=%*pbl act=%*pbl\n", ((struct file_kobject *)kobj)->dev, ((struct file_kobject *)kobj)->ino, CONFIG_MEDUSA_VS, &((struct file_kobject *)kobj)->med_object.vs, CONFIG_MEDUSA_ACT, &((struct file_kobject *)kobj)->med_object.act); */

out_err_update:
	__unlookup();
	return retval;
}

/* third, we will define the kclass, describing such objects */
/* that's for L3, to make it happy */

MED_KCLASS(file_kobject) {
	MEDUSA_KCLASS_HEADER(file_kobject),
	"file",

	NULL,		/* init kclass */
	NULL,		/* destroy kclass */
	file_fetch,	/* fetch kobject */
	file_update,	/* update kobject */
	file_unmonitor,	/* disable all monitoring on kobj. */
};

int __init file_kobject_init(void)
{
	MED_REGISTER_KCLASS(file_kobject);
	return 0;
}

device_initcall(file_kobject_init);

// SPDX-License-Identifier: GPL-2.0

/* (C) 2002 Milan Pikula */

#include <linux/fs_struct.h>
#include <linux/namei.h>
#include "../../../fs/mount.h" /* real_mount() */

#include "l3/registry.h"
#include "l2/kobject_process.h"
#include "l2/kobject_file.h"

/* the getfile event types (yes, there are more of them) are a bit special:
 * 1) they are called from the beginning of various access types to get the
 *    initial VS set,
 * 2) they gain some additional information, which enables L4 code to keep
 *    the file hierarchy, if it wants.
 * 3) due to creepy VFS design in Linux we sometimes do some magic.
 */

struct getfile_event {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
	int pid;
};

MED_ATTRS(getfile_event) {
	MED_ATTR_RO(getfile_event, filename, "filename", MED_STRING),
	MED_ATTR_RO(getfile_event, pid, "pid", MED_SIGNED),
	MED_ATTR_END
};
MED_EVTYPE(getfile_event, "getfile", file_kobject, "file",
		file_kobject, "parent");

/**
 * medusa_evocate_mnt - find the uppermost struct vfsmount for given dentry/inode.
 * @dentry: dentry to perform lookup on.
 *
 * This is a helper routine for file_kobj_validate_dentry. It does the black
 * magic to get the needed information, and owes for its existence to
 * the dirty design of VFS, where some parts of information are just missing.
 * From all possible vfsmounts, we must return the uppermost one to get
 * it right; and we try to avoid recursion 'cause we value the stack.
 */

struct vfsmount *medusa_evocate_mnt(struct dentry *dentry)
{
	int depth, last_depth, maxdepth, can_nest;
	struct mount *p;
	int count = 0;

	/* get the local root */
	//spin_lock(&dcache_lock);
	//spin_lock(&dentry->d_lock);
	while (!IS_ROOT(dentry)) {
		//struct dentry *old = dentry;
		dentry = dentry->d_parent;
		//spin_lock(&dentry->d_lock);
		//spin_unlock(&old->d_lock);
	}
	dget(dentry);
	//spin_unlock(&dentry->d_lock);
	//spin_unlock(&dcache_lock);

	maxdepth = 0;
	do {
		can_nest = 0;
		last_depth = -1; depth = 0;

		/* hope that init isn't chrooted; get "global" root */
		spin_lock(&init_task.fs->lock);
		p = real_mount(init_task.fs->root.mnt);
		while (p->mnt_parent != p->mnt_parent->mnt_parent)
			p = p->mnt_parent;
		mntget(&p->mnt);
		spin_unlock(&init_task.fs->lock);

		//spin_lock(&dcache_lock);
		do {
			count++;
			if (depth == maxdepth) {
				if (p->mnt.mnt_root == dentry) {
					//spin_unlock(&dcache_lock);
					dput(dentry);
					return &p->mnt;
				}
				can_nest = can_nest || !list_empty(&(p->mnt_mounts));
			}
			if ((depth < maxdepth) && (last_depth <= depth) && !list_empty(&(p->mnt_mounts))) {

				mntput(&p->mnt);
				p = real_mount(mntget(&list_entry((p->mnt_mounts.next), struct mount, mnt_child)->mnt));
				last_depth = depth++;
				continue;

			}
			if (!list_empty(&(p->mnt_child)) && list_entry((p->mnt_child.next), struct mount, mnt_mounts) != p->mnt_parent) {

				mntput(&p->mnt);
				p = real_mount(mntget(&list_entry((p->mnt_child.next), struct mount, mnt_child)->mnt));
				last_depth = depth;
				continue;

			}

			mntput(&p->mnt);
			p = real_mount(mntget(&p->mnt_parent->mnt));
			last_depth = depth--;

		} while (depth >= 0);
		//spin_unlock(&dcache_lock);
		mntput(&p->mnt);
		maxdepth++;
	} while (can_nest);

	dput(dentry);
	med_pr_notice("Fatal error: too drunk to evocate mnt. Returning init's mnt instead.\n");
	return mntget(init_task.fs->root.mnt);
}

static enum medusa_answer_t do_file_kobj_validate_dentry(struct path *ndcurrent,
		struct path *ndupper, struct path *ndparent);

void medusa_clean_inode(struct inode *inode)
{
	init_med_object(&inode_security(inode)->med_object);
}

void inline info_mnt(struct mount *mnt)
{
	pr_cont("mountpoint: %pd, vfs mnt root: %pd\n", mnt->mnt_mountpoint, mnt->mnt.mnt_root);
}

void medusa_get_upper_and_parent(const struct path *ndsource,
		struct path *ndupperp, struct path *ndparentp)
{
	/* med_pr_info("medusa_get_upper_and_parent: dentry %pd4\n", ndsource->dentry); */
	*ndupperp = *ndsource;
	dget(ndupperp->dentry);
	if (ndupperp->mnt) {
		mntget(ndupperp->mnt);
	}
	else if (IS_ROOT(ndupperp->dentry)) {
		/* We don't know `mnt` and `ndupperp` doesn't have a parent
		 * (it's a root dentry. This code searches for `struct vfsmount`
		 * for the given dentry. This is needed when we have an inode
		 * (from an inode hook). We don't need to run
		 * `medusa_evocate_mnt` for paths from path hooks. */
		ndupperp->mnt = medusa_evocate_mnt(ndupperp->dentry); /* FIXME: may fail [?] */
	}

	while (IS_ROOT(ndupperp->dentry)) {
		/* Cycle runs until we find a dentry that *isn't* a root. */
		struct vfsmount *tmp;
		if (real_mount(ndupperp->mnt)->mnt_parent == real_mount(ndupperp->mnt)->mnt_parent->mnt_parent) {
			/* We are already on the / filesystem (not on some
			 * mounted filesystem). Break here because we don't want
			 * the / directory. */
			/* med_pr_info("medusa_get_upper_and_parent: at root: %pd4, source: %pd4\n", real_mount(ndupperp->mnt)->mnt_parent->mnt_mountpoint, ndsource->dentry); */
			break;
		}
		/* Go to the upper mountpoint. First entry for the mountpoint
		 * from the outer filesystem. */
		dput(ndupperp->dentry);
		ndupperp->dentry = dget(real_mount(ndupperp->mnt)->mnt_mountpoint);
		/* And then its `struct mount`. */
		tmp = mntget(&real_mount(ndupperp->mnt)->mnt_parent->mnt);
		mntput(ndupperp->mnt);
		ndupperp->mnt = tmp;
	}
	if (ndparentp) {
		/* The caller requested parent dentry. */
		if (IS_ROOT(ndupperp->dentry)) {
			/* This is a disconnected root. */
			*ndparentp = *ndsource;
		}
		else {
			/* If it's not a root, we get the parent from
			 * `ndupperp`. */
			ndparentp->dentry = ndupperp->dentry->d_parent;
			ndparentp->mnt = ndupperp->mnt;
		}
		dget(ndparentp->dentry);
		if (ndparentp->mnt)
			mntget(ndparentp->mnt);
	}

	/* Now we have dentry and mnt. If IS_ROOT(dentry) then the dentry is global filesystem root */
}

void medusa_put_upper_and_parent(struct path *ndupper, struct path *ndparent)
{
	if (ndupper) {
		dput(ndupper->dentry);
		if (ndupper->mnt)
			mntput(ndupper->mnt);
	}
	if (ndparent) {
		dput(ndparent->dentry);
		if (ndparent->mnt)
			mntput(ndparent->mnt);
	}
}

/**
 * Checks for correctness of current, upper and parent.
 * @returns: new dir for next dentry computed from ndparent
 */
struct path check(struct dentry* dentry, struct path* dir, struct path* c, struct path* u, struct path* p)
{
	struct path ndcurrent;
	struct path ndupper;
	struct path ndparent;

	ndcurrent.dentry = dentry;
	ndcurrent.mnt = dir->mnt; /* may be NULL */

	ndupper = ndcurrent;

	if (IS_ROOT(dentry)) {
		path_get(&ndupper);  // it will be put in follow_up()
		follow_up(&ndupper);
	}
	ndparent.dentry = ndupper.dentry->d_parent;
	ndparent.mnt = ndupper.mnt;

	if (!path_equal(c, &ndcurrent)) {
		pr_warn("current not equal: %pd != %pd\n", ndcurrent.dentry, c->dentry);
		info_mnt(real_mount(ndcurrent.mnt));
		if (c->mnt)
			info_mnt(real_mount(c->mnt));
		else
			med_pr_info("mnt is null\n");
	}
	if (!path_equal(u, &ndupper)) {
		pr_warn("upper not equal: %pd != %pd\n", ndupper.dentry, u->dentry);
		info_mnt(real_mount(ndupper.mnt));
		if (u->mnt)
			info_mnt(real_mount(u->mnt));
		else
			med_pr_info("mnt is null\n");
	}
	if (!path_equal(p, &ndparent)) {
		pr_warn("parent not equal: %pd != %pd\n", ndparent.dentry, p->dentry);
		info_mnt(real_mount(ndparent.mnt));
		if (p->mnt)
			info_mnt(real_mount(p->mnt));
		else
			med_pr_info("mnt is null\n");
	}

	if (IS_ROOT(dentry)) {
		path_put(&ndupper);
	}

	return (struct path) {.mnt = ndparent.mnt,
			.dentry = ndparent.dentry->d_parent};
}

int file_kobj_validate_dentry_dir(const struct vfsmount* mnt, struct dentry *dentry)
{
	struct path ndcurrent;
	struct path ndupper;
	struct path ndparent;
	struct path parent_dir;
	struct medusa_l1_inode_s *ndcurrent_inode;
	struct medusa_l1_inode_s *ndparent_inode;

	/* nothing to do if there is no running authserver */
	if (!med_is_authserver_present())
		return 0;

	medusa_clean_inode(dentry->d_inode);
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
	cap_clear(inode_security(dentry->d_inode)->pcap);
	inode_security(dentry->d_inode)->icap = CAP_FULL_SET;
	inode_security(dentry->d_inode)->ecap = CAP_FULL_SET;
#endif
	ndcurrent.dentry = dentry;
	ndcurrent.mnt = mnt;

	ndupper = ndcurrent;

	path_get(&ndupper);	// it will be put in follow_up() and new path will
				// be returned (that has to be put also)
	if (IS_ROOT(dentry)) {
		follow_up(&ndupper);
	}
	ndparent.dentry = ndupper.dentry->d_parent;
	ndparent.mnt = ndupper.mnt;

	if (ndparent.dentry->d_inode == NULL) {
		path_put(&ndupper);
		return 0;
	}

	if (ndcurrent.dentry != ndparent.dentry) {
		parent_dir = (struct path) {.mnt = ndparent.mnt,
			                    .dentry = ndparent.dentry};
		if (!is_med_magic_valid(&inode_security(ndparent.dentry->d_inode)->med_object) &&
			file_kobj_validate_dentry_dir(parent_dir.mnt, ndparent.dentry) <= 0) {
			path_put(&ndupper);
			return 0;
		}

		/*
		 * If triggering of the getfile event in the parent's security
		 * information field is turned off, take the VS model for a new
		 * Medusa's file object from its parent.
		 */
		if (!MEDUSA_MONITORED_ACCESS_O(getfile_event,
					inode_security(ndparent.dentry->d_inode))) {
			/* med_pr_info("validate_dentry_dir %pd4 inheriting from %pd4\n", ndcurrent.dentry, ndparent.dentry); */
			ndcurrent_inode = inode_security(ndcurrent.dentry->d_inode);
			ndparent_inode = inode_security(ndparent.dentry->d_inode);
			ndcurrent_inode->med_object = ndparent_inode->med_object;
			inode_security(ndcurrent.dentry->d_inode)->user = inode_security(ndparent.dentry->d_inode)->user;
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
			inode_security(ndcurrent.dentry->d_inode)->icap = inode_security(ndparent.dentry->d_inode)->icap;
			inode_security(ndcurrent.dentry->d_inode)->pcap = inode_security(ndparent.dentry->d_inode)->pcap;
			inode_security(ndcurrent.dentry->d_inode)->ecap = inode_security(ndparent.dentry->d_inode)->ecap;
#endif
			path_put(&ndupper);
			return 1;
		}
	}

	/* we're global root, or cannot inherit from our parent */

	if (do_file_kobj_validate_dentry(&ndcurrent, &ndupper, &ndparent)
			!= MED_ERR) {
		path_put(&ndupper);
		return is_med_magic_valid(&inode_security(ndcurrent.dentry->d_inode)->med_object);
	}
	path_put(&ndupper);
	return -1;
}

int medusa_l1_inode_alloc_security(struct inode *inode);
/**
 * file_kobj_validate_dentry - get dentry security information from auth. server
 * @dentry: dentry to get the information for.
 * @mnt: optional vfsmount structure for that dentry
 *
 * This routine expects the existing, but !is_med_magic_valid Medusa dentry's inode security struct!
 */
int file_kobj_validate_dentry(struct dentry *dentry, struct vfsmount *mnt, struct path *dir)
{
	struct path ndcurrent;
	struct path ndupper;
	struct path ndparent;
	struct medusa_l1_inode_s *ndcurrent_inode;
	struct medusa_l1_inode_s *ndparent_inode;
	struct path parent_dir;

	/* nothing to do if there is no running authserver */
	if (!med_is_authserver_present())
		return 0;

	init_med_object(&(inode_security(dentry->d_inode)->med_object));
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
	cap_clear(inode_security(dentry->d_inode)->pcap);
	inode_security(dentry->d_inode)->icap = CAP_FULL_SET;
	inode_security(dentry->d_inode)->ecap = CAP_FULL_SET;
#endif
	ndcurrent.dentry = dentry;
	ndcurrent.mnt = mnt; /* may be NULL */
	/* When using path hooks, we will have `mnt`. */
	medusa_get_upper_and_parent(&ndcurrent, &ndupper, &ndparent);
	/* med_pr_info("current: %pd upper: %pd parent: %pd\n", ndcurrent.dentry, ndupper.dentry, ndparent.dentry); */
	//if (ndcurrent.mnt)
	//	info_mnt(real_mount(ndcurrent.mnt));
	//if (ndupper.mnt)
	//	info_mnt(real_mount(ndupper.mnt));
	//if (ndparent.mnt)
	//	info_mnt(real_mount(ndparent.mnt));
	//parent_dir = check(dentry, dir, &ndcurrent, &ndupper, &ndparent);

	if (ndparent.dentry->d_inode == NULL) {
		medusa_put_upper_and_parent(&ndupper, &ndparent);
		return 0;
	}

	if (ndcurrent.dentry != ndparent.dentry) {
		if (!is_med_magic_valid(&(inode_security(ndparent.dentry->d_inode)->med_object)) &&
			file_kobj_validate_dentry(ndparent.dentry, ndparent.mnt, &parent_dir) <= 0) {
			medusa_put_upper_and_parent(&ndupper, &ndparent);
			return 0;
		}

		/*
		 * If triggering of the getfile event in the parent's security
		 * information field is turned off, take the VS model for a new
		 * Medusa's file object from its parent.
		 */
		if (!MEDUSA_MONITORED_ACCESS_O(getfile_event,
					inode_security(ndparent.dentry->d_inode))) {
			/* med_pr_info("validate_dentry %pd4 inheriting from %pd4\n", ndcurrent.dentry, ndparent.dentry); */
			ndcurrent_inode = inode_security(ndcurrent.dentry->d_inode);
			ndparent_inode = inode_security(ndparent.dentry->d_inode);
			ndcurrent_inode->med_object = ndparent_inode->med_object;
			inode_security(ndcurrent.dentry->d_inode)->user = inode_security(ndparent.dentry->d_inode)->user;
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
			inode_security(ndcurrent.dentry->d_inode)->icap = inode_security(ndparent.dentry->d_inode)->icap;
			inode_security(ndcurrent.dentry->d_inode)->pcap = inode_security(ndparent.dentry->d_inode)->pcap;
			inode_security(ndcurrent.dentry->d_inode)->ecap = inode_security(ndparent.dentry->d_inode)->ecap;
#endif
			medusa_put_upper_and_parent(&ndupper, &ndparent);
			return 1;
		}
	}

	/* we're global root, or cannot inherit from our parent */

	if (do_file_kobj_validate_dentry(&ndcurrent, &ndupper, &ndparent)
			!= MED_ERR) {
		medusa_put_upper_and_parent(&ndupper, &ndparent);
		return is_med_magic_valid(&(inode_security(ndcurrent.dentry->d_inode)->med_object));
	}
	medusa_put_upper_and_parent(&ndupper, &ndparent);
	return -1;
}

static enum medusa_answer_t do_file_kobj_validate_dentry(struct path *ndcurrent,
		struct path *ndupper, struct path *ndparent)
{
	struct getfile_event event;
	struct file_kobject file;
	struct file_kobject directory;
	enum medusa_answer_t retval;
	/* med_pr_info("do_validate_dentry: current=%pd4 parent=%pd4\n", ndcurrent->dentry, ndparent->dentry); */
	/* med_pr_info("nducurrent: %pd4", ndcurrent->dentry); */
	/* med_pr_info("ndparent: %pd4\n", ndparent->dentry); */
	file_kern2kobj(&file, ndcurrent->dentry->d_inode);
	file_kobj_dentry2string_dir(ndparent, ndupper->dentry, event.filename);
	file_kern2kobj(&directory, ndparent->dentry->d_inode);
	file_kobj_live_add(ndcurrent->dentry->d_inode);
	file_kobj_live_add(ndparent->dentry->d_inode);
	event.pid = current->pid;
	retval = MED_DECIDE(getfile_event, &event, &file, &directory);
	file_kobj_live_remove(ndparent->dentry->d_inode);
	file_kobj_live_remove(ndcurrent->dentry->d_inode);
	return retval;
}

int __init getfile_evtype_init(void)
{
	/*
	 * Triggering of this event can be turned off to permit VS model
	 * inheriting: if parent of newly created Medusa's file object does not
	 * trigger getfile event, the new object inherites parent's VS model.
	 */
	MED_REGISTER_EVTYPE(getfile_event,
			MEDUSA_EVTYPE_TRIGGEREDATSUBJECT |
			MEDUSA_EVTYPE_TRIGGEREDBYOBJECTBIT);
	return 0;
}
device_initcall(getfile_evtype_init);

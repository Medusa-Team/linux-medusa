// SPDX-License-Identifier: GPL-2.0

/* (C) 2020 Matus Jokay */

#include <linux/namei.h>
#include <linux/path.h>
#include <linux/crc32.h>
/* we need internal fs function 'user_get_super' */
#include "../../fs/internal.h"
#include "l3/registry.h"
#include "l2/kobject_fuck.h"

#define ACT_TEST 0	/* existence test for an entry in a hash table */
#define ACT_REMOVE 1	/* remove entry from a hash table */
#define ACT_APPEND 2	/* add entry to a hash table */
#define is_allowed_path(path, inode) \
	do_allowed_path(path, inode, ACT_TEST)
#define remove_from_allowed_paths(path, inode) \
	do_allowed_path(path, inode, ACT_REMOVE)
#define append_to_allowed_paths(path, inode) \
	do_allowed_path(path, inode, ACT_APPEND)

// TODO add choices to menu config
#define hash_function(path) crc32(0, path, strlen(path))

extern seqlock_t mount_lock;

MED_ATTRS(fuck_kobject) {
	MED_ATTR(fuck_kobject, path, "path", MED_STRING),
	MED_ATTR(fuck_kobject, ino, "ino", MED_UNSIGNED), // unsigned long
	MED_ATTR(fuck_kobject, dev, "dev", MED_UNSIGNED), // unsigned int
	MED_ATTR(fuck_kobject, action, "action", MED_STRING),
	MED_ATTR_END
};

struct fuck_path {
	struct hlist_node list;
	char path[0];
};

/**
 * Inspired by apparmor/path.c and fs/d_path.c.
 * For comments see fs/d_path.c!
 */
static int prepend(char *buffer, int buflen, const struct qstr *name)
{
	const char *dname;
	u32 dlen;

	dname = smp_load_acquire(&name->name);
	dlen = READ_ONCE(name->len);

	buflen -= dlen;
	if (buflen < 0)
		return -ENAMETOOLONG;
	memcpy(buffer+buflen, dname, dlen);

	return dlen;
}

/**
 * Taken and modified from fs/d_path.c.
 */
static int prepend_dentry_name(char *buf, int buflen, struct dentry *dentry)
{
	unsigned seq, m_seq = 0;
	int ret;

	rcu_read_lock();
restart_mnt:
	read_seqbegin_or_lock(&mount_lock, &m_seq);
	seq = 0;
	rcu_read_lock();
restart:
	read_seqbegin_or_lock(&rename_lock, &seq);
	ret = prepend(buf, buflen, &d_backing_dentry(dentry)->d_name);
	if (!(seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&rename_lock, seq)) {
		seq = 1;
		goto restart;
	}
	done_seqretry(&rename_lock, seq);

	if (!(m_seq & 1))
		rcu_read_unlock();
	if (need_seqretry(&mount_lock, m_seq)) {
		m_seq = 1;
		goto restart_mnt;
	}
	done_seqretry(&mount_lock, m_seq);

	return ret;
}

/**
 * Return %true if @path is in allowed paths in security blob of the @inode,
 * %false otherwise.
 *
 * If @action is ACT_REMOVE and @path is in allowed paths, the @path is
 * removed from the list of allowed paths.
 * If @action is ACT_APPEND and @path is not in allowed paths, the @path
 * is appended to the list of allowed paths.
 */
static bool do_allowed_path(char *path, struct medusa_l1_inode_s *inode,
			    int action)
{
	struct fuck_path *secure_path;
	struct hlist_node *tmp;
	int len;
	u32 hash;

	hash = hash_function(path);
	hash_for_each_possible_safe(inode->fuck, secure_path, tmp, list, hash) {
		if (strncmp(path, secure_path->path, PATH_MAX) == 0) {
			if (action == ACT_REMOVE) {
				hash_del(&secure_path->list);
				kfree(secure_path);
			}
			/* If @action is %ACT_APPEND and corresponding entry is
			 * found, appending is silently ignored to not introduce
			 * duplicity in the hash table.
			 */
			return true;
		}
	}

	/* If @action is %ACT_TEST or %ACT_REMOVE and the corresponding entry is
	 * not found in the hash table, return %false.
	 */
	if (action != ACT_APPEND)
		return false;

	len = strlen(path) + 1;
	secure_path = kmalloc(sizeof(struct fuck_path) + sizeof(char)*len, GFP_KERNEL);
	if (!secure_path)
		return false;
	strncpy(secure_path->path, path, len);
	secure_path->path[len-1] = '\0';
	hash_add(inode->fuck, &secure_path->list, hash);

	return true;
}

int fuck_free(struct medusa_l1_inode_s *med)
{
	struct fuck_path *path;
	struct hlist_node *tmp;
	int bucket;

	hash_for_each_safe(med->fuck, bucket, tmp, path, list) {
		hash_del(&path->list);
		kfree(path);
	}

	return 0;
}

/**
 * Check whether access to a @dentry from the @path is allowed or not. If a
 * dentry @new is not %NULL, it's the last element of the examined path.
 *
 * Returns 1 if the access is granted, 0 if the access is denied and a value
 * less than zero in the case of an error.
 */
int allow_fuck(struct dentry *dentry, const struct path *path, struct dentry *new)
{
	struct inode *fuck_inode = d_backing_inode(dentry);
	char *buf, *examined_path, term = '\0';
	int buflen = PATH_MAX, newnamelen = 0, ret = 1;

	/* if inode has no protected paths defined, allow access */
	if (likely(hash_empty(inode_security(fuck_inode)->fuck)))
		return 1;

	buf = __getname();
	if (!buf) {
		med_pr_err("%s: OOM", __func__);
		return -ENOMEM;
	}

	/* `d_absolute_path()` stores the path string from the end of the buffer
	 * included terminating character; a new dentry name should be therefore
	 * stored from the end of the buffer, too.
	 */
	if (new) {
		buf[buflen-1] = '\0';
		buflen--;

		ret = prepend_dentry_name(buf, buflen, new);
		if (unlikely(ret < 0)) {
			med_pr_err("%s: prepend_dentry_name() failed with %d",
				   __func__, ret);
			goto out_allow_fuck;
		}
		else if (unlikely(!ret)) {
			med_pr_warn("%s: ooops, dentry name is empty!", __func__);
			ret = -EINVAL;
			goto out_allow_fuck;
		}
		newnamelen = ret;
		buflen -= ret;
		term = '/';
		ret = 1;
	}

	examined_path = d_absolute_path(path, buf, buflen);
	/* `d_absolute_path()` may return EINVAL or ENAMETOOLONG */
	if (IS_ERR(examined_path)) {
		ret = PTR_ERR(examined_path);
		med_pr_err("%s: d_absolute_path() failed with %d",
			   __func__, ret);
		goto out_allow_fuck;
	}
	/* Change terminating character stored by `d_absolute_path()` to '/' if
	 * necessary.
	 */
	buf[buflen-1] = term;

	if (!is_allowed_path(examined_path, inode_security(fuck_inode))) {
		med_pr_info("%s: denied access from the path '%s'", __func__,
			    examined_path);
		ret = 0;
		goto out_allow_fuck;
	}
	med_pr_info("%s: access granted from the path '%s'", __func__,
		    examined_path);

out_allow_fuck:
	__putname(buf);
	return ret;
}

static struct medusa_kobject_s *fuck_fetch(struct medusa_kobject_s *kobj)
{
	struct fuck_kobject *fkobj = (struct fuck_kobject *) kobj;
	struct inode *fuck_inode;
	struct path path;

	fkobj->path[sizeof(fkobj->path)-1] = '\0';
	if (kern_path(fkobj->path, LOOKUP_FOLLOW, &path) < 0)
		return NULL;

	fuck_inode = d_backing_inode(path.dentry);
	fkobj->ino = fuck_inode->i_ino;
	fkobj->dev = new_encode_dev(fuck_inode->i_sb->s_dev);
	memset(fkobj->action, '\0', sizeof(fkobj->action));

	return (struct medusa_kobject_s *) kobj;
}

/**
 *	  fuck_update - update allowed path list for given dev/ino file
 *	  @kobj:  fuck_kobject with filled 'dev', 'ino', 'path' and 'action' values
 *
 *	  Add or remove allowed 'path' for given file (identified by dev/ino values).
 *	  fuck_kobject:
 *			  'dev':  identification of device
 *			  'ino':  inode number on the device
 *			  'path': allowed access path to be added/removed for file identified by dev/ino
 *			  'action': action to be done, can be:
 *					  'remove': removes 'path' from allowed access paths for dev/ino
 *					  'append': add 'path' to allowed access paths for dev/ino
 *
 *	  return values:
 *			  MED_ALLOW:
 *					  - successfully appended/removed path
 *					  - attempt to remove path from empty list
 *					  - attempt to remove non-existing path in list
 *			  MED_ERR:
 *					  - unable to get info about file specified by dev/ino numbers
 *					  - memory allocation error
 */
static enum medusa_answer_t fuck_update(struct medusa_kobject_s *kobj)
{
	struct fuck_kobject *fkobj =  (struct fuck_kobject *) kobj;
	struct super_block *sb;
	struct inode *fuck_inode;

	sb = user_get_super(new_decode_dev(fkobj->dev), false);
	if (!sb) {
		med_pr_warn("device %d not found", fkobj->dev);
		return MED_ERR;
	}
	fuck_inode = ilookup(sb, fkobj->ino);
	drop_super(sb);

	if (!fuck_inode) {
		med_pr_warn("inode %ld on dev %d not found in the cache",
			    fkobj->ino, fkobj->dev);
		return MED_ERR;
	}

	fkobj->path[sizeof(fkobj->path)-1] = '\0';
	if (strcmp(fkobj->action, "append") == 0) {
		if (!append_to_allowed_paths(fkobj->path, inode_security(fuck_inode))) {
			med_pr_warn("%s: OOM ino %ld dev %d", __func__, fkobj->ino, fkobj->dev);
			iput(fuck_inode);
			return MED_ERR;
		}
	} else if (strcmp(fkobj->action, "remove") == 0) {
		/* removing non-existing path from allowed paths is silently ignored */
		remove_from_allowed_paths(fkobj->path, inode_security(fuck_inode));
	}

	med_pr_info("%s: '%s' (dev = %u, ino = %lu, act = %s)", __func__,
		     fkobj->path, fkobj->dev, fkobj->ino, fkobj->action);

	iput(fuck_inode);
	return MED_ALLOW;
}

MED_KCLASS(fuck_kobject) {
	MEDUSA_KCLASS_HEADER(fuck_kobject),
	"fuck",
	NULL,		/* init kclass */
	NULL,		/* destroy kclass */
	fuck_fetch,
	fuck_update,
	NULL,		/* unmonitor */
};

int __init fuck_kobject_init(void)
{
	MED_REGISTER_KCLASS(fuck_kobject);
	return 0;
}

device_initcall(fuck_kobject_init);

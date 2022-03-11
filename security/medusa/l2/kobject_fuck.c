// SPDX-License-Identifier: GPL-2.0

/* (C) 2020 Matus Jokay */

#include <linux/namei.h>
#include <linux/path.h>
#include <linux/crc32.h>
/* we need internal fs function 'user_get_super' */
#include "../../fs/internal.h"
#include "l3/registry.h"
#include "l2/kobject_fuck.h"

extern seqlock_t mount_lock;

MED_ATTRS(fuck_kobject) {
	MED_ATTR(fuck_kobject, path, "path", MED_STRING),
	MED_ATTR(fuck_kobject, ino, "ino", MED_UNSIGNED), // unsigned long
	MED_ATTR(fuck_kobject, dev, "dev", MED_UNSIGNED), // unsigned int
	MED_ATTR(fuck_kobject, action, "action", MED_STRING),
	MED_ATTR_END
};

// TODO add choices to menu config
#define hash_function(path) crc32(0, path, strlen(path))

struct fuck_path {
	struct hlist_node list;
	char path[0];
};

/*
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

/*
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

static struct fuck_path *get_from_hash(char *path, int hash, struct medusa_l1_inode_s *inode)
{
	struct fuck_path *fuck_item;

	hash_for_each_possible(inode->fuck, fuck_item, list, hash) {
		if (strncmp(path, fuck_item->path, PATH_MAX) == 0)
			return fuck_item;
	}

	return NULL;
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

//used in medusa_l1_path_chown, medusa_l1_path_chmod, medusa_l1_file_open
int validate_fuck(const struct path *fuck_path)
{
	struct inode *fuck_inode = fuck_path->dentry->d_inode;
	int hash, ret = 0;
	char *accessed_path;
	char *buf = NULL;

	if (unlikely(!fuck_inode)) {
		med_pr_info("medusa: empty inode\n");
		goto out;
	}

	if (likely(hash_empty(inode_security(fuck_inode)->fuck)))
		goto out;

	buf = kmalloc(sizeof(char) * (PATH_MAX + 1), GFP_KERNEL);
	if (unlikely(!buf))
		goto out;

	accessed_path = d_absolute_path(fuck_path, buf, sizeof(buf));
	if (!unlikely(accessed_path || IS_ERR(accessed_path))) {
		/* accessed_path is NULL */
		goto out;
	}

	hash = hash_function(accessed_path);
	if (likely(get_from_hash(accessed_path, hash, inode_security(fuck_inode)) == NULL)) {
		med_pr_notice("VALIDATE_FUCK: denied path (not defined in allowed path list)\n");
		ret = -EPERM;
	}
	med_pr_debug("VALIDATE_FUCK: accessed_path: %s inode: %lu result: %d\n", accessed_path, fuck_inode->i_ino, ret);
out:
	kfree(buf);
	return ret;
}

// used in medusa_l1_path_link
int allow_fuck(struct dentry *dentry, const struct path *path, struct dentry *new)
{
	struct inode *fuck_inode = d_backing_inode(dentry);
	char *buf, *examined_path, term = '\0';
	int buflen = PATH_MAX, newnamelen = 0, ret = 0;

	/* if inode has no protected paths defined, allow hard link */
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
	if (unlikely(new)) {
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
		ret = 0;
		term = '/';
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

	med_pr_info("%s: examined path='%s'", __func__, examined_path);

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
	struct fuck_path *fuck_path;
	int hash;

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
	hash = hash_function(fkobj->path);

	if (strcmp(fkobj->action, "append") == 0) {
		fuck_path = kzalloc(sizeof(struct fuck_path) + sizeof(char)*strnlen(fkobj->path, PATH_MAX), GFP_KERNEL);
		if (!fuck_path) {
			med_pr_warn("OOM ino %ld dev %d", fkobj->ino, fkobj->dev);
			iput(fuck_inode);
			return MED_ERR;
		}
		strncpy(fuck_path->path, fkobj->path, PATH_MAX-1);

		/* Don't check for duplicity in hash table.
		 * Is up to admin do not add the same 'path' more than once.
		 */
		hash_add(inode_security(fuck_inode)->fuck, &fuck_path->list, hash);
	} else if (strcmp(fkobj->action, "remove") == 0) {
		/* remove non-existing path in hash table is ok */
		fuck_path = get_from_hash(fkobj->path, hash, inode_security(fuck_inode));
		if (!fuck_path)
			goto out;
		hash_del(&fuck_path->list);
		kfree(fuck_path);
	}

	med_pr_info("Fuck: '%s' (dev = %u, ino = %lu, act = %s)",
		     fkobj->path, fkobj->dev, fkobj->ino, fkobj->action);

out:
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

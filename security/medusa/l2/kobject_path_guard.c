// SPDX-License-Identifier: GPL-2.0

/* (C) 2020 Matus Jokay */

#include <linux/namei.h>
#include <linux/path.h>
#include <linux/module.h>
#include <linux/unaligned.h>
#include <crypto/hash.h>
/* we need internal fs function 'user_get_super' */
#include "../../fs/internal.h"
#include "l3/registry.h"
#include "l2/kobject_path_guard.h"
#include "l2/kobject_path_guard_hash.h"

enum path_guard_action {
	PATH_GUARD_LOOKUP,
	PATH_GUARD_REMOVE,
	PATH_GUARD_APPEND,
};

static struct crypto_shash *hash_transformation;

static struct kmem_cache *path_guard_cache;

MED_ATTRS(path_guard_kobject) {
	MED_ATTR(path_guard_kobject, path, "path", MED_STRING),
	MED_ATTR(path_guard_kobject, ino, "ino", MED_UNSIGNED), /* unsigned long */
	MED_ATTR(path_guard_kobject, dev, "dev", MED_UNSIGNED), /* unsigned int */
	MED_ATTR(path_guard_kobject, action, "action", MED_STRING),
	MED_ATTR_END
};

struct path_guard_entry {
	struct hlist_node list;
	char path_hash[PATH_GUARD_HASH_DIGEST_SIZE];
};

bool path_guard_is_ready(void)
{
	return hash_transformation && path_guard_cache;
}

/*
 * Calculate hash of @path and save it into @hash_result.
 *
 * Return 0 if the path was hashed successfully; < 0 if an error occurred.
 */
static int path_guard_hash(const char *path,
			   char hash_result[PATH_GUARD_HASH_DIGEST_SIZE])
{
	SHASH_DESC_ON_STACK(sdesc, hash_transformation);

	sdesc->tfm = hash_transformation;
	return crypto_shash_digest(sdesc, path, strlen(path), hash_result);
}

/*
 * Return %true if @path is in allowed paths in security blob of the @inode,
 * %false otherwise.
 *
 * If @action is PATH_GUARD_REMOVE and @path is in allowed paths, the @path is
 * removed from the list of allowed paths.
 * If @action is PATH_GUARD_APPEND and @path is not in allowed paths, the
 * @path is appended to the list of allowed paths.
 */
static bool path_guard_apply(const char *path,
			     struct medusa_l1_inode_s *context,
			     enum path_guard_action action)
{
	struct path_guard_entry *new_entry = NULL;
	struct path_guard_entry *entry;
	struct hlist_node *tmp;
	unsigned long flags;
	u64 hash;
	char path_hash[PATH_GUARD_HASH_DIGEST_SIZE];
	int err;

	if (!path || !context || !path_guard_is_ready())
		return false;
	err = path_guard_hash(path, path_hash);
	if (err) {
		med_pr_err("%s: hashing path failed, error=%d", __func__, err);
		return false;
	}
	hash = get_unaligned_le64(path_hash);
	if (action == PATH_GUARD_APPEND) {
		new_entry = kmem_cache_alloc(path_guard_cache, GFP_KERNEL);
		if (!new_entry)
			return false;
		memcpy(new_entry->path_hash, path_hash,
		       PATH_GUARD_HASH_DIGEST_SIZE);
	}

	spin_lock_irqsave(&context->path_guard_lock, flags);
	hash_for_each_possible_safe(context->path_guard, entry, tmp, list,
				    hash) {
		if (!memcmp(path_hash, entry->path_hash,
			    PATH_GUARD_HASH_DIGEST_SIZE)) {
			if (action == PATH_GUARD_REMOVE)
				hash_del(&entry->list);
			spin_unlock_irqrestore(&context->path_guard_lock, flags);
			if (action == PATH_GUARD_REMOVE)
				kmem_cache_free(path_guard_cache, entry);
			else if (action == PATH_GUARD_APPEND)
				kmem_cache_free(path_guard_cache, new_entry);
			return true;
		}
	}

	if (action != PATH_GUARD_APPEND) {
		spin_unlock_irqrestore(&context->path_guard_lock, flags);
		return false;
	}
	hash_add(context->path_guard, &new_entry->list, hash);
	spin_unlock_irqrestore(&context->path_guard_lock, flags);

	return true;
}

bool path_guard_path_is_allowed(const char *path,
				struct medusa_l1_inode_s *context)
{
	return path_guard_apply(path, context, PATH_GUARD_LOOKUP);
}

bool path_guard_path_add(const char *path,
			 struct medusa_l1_inode_s *context)
{
	return path_guard_apply(path, context, PATH_GUARD_APPEND);
}

bool path_guard_path_remove(const char *path,
			    struct medusa_l1_inode_s *context)
{
	return path_guard_apply(path, context, PATH_GUARD_REMOVE);
}

bool path_guard_has_entries(struct medusa_l1_inode_s *context)
{
	unsigned long flags;
	bool result;

	if (!context)
		return false;
	spin_lock_irqsave(&context->path_guard_lock, flags);
	result = !hash_empty(context->path_guard);
	spin_unlock_irqrestore(&context->path_guard_lock, flags);
	return result;
}

int path_guard_free(struct medusa_l1_inode_s *med)
{
	HLIST_HEAD(entries);
	struct path_guard_entry *entry;
	struct hlist_node *tmp;
	unsigned long flags;
	int bucket;

	if (!med)
		return -EINVAL;
	spin_lock_irqsave(&med->path_guard_lock, flags);
	hash_for_each_safe(med->path_guard, bucket, tmp, entry, list) {
		hash_del(&entry->list);
		hlist_add_head(&entry->list, &entries);
	}
	spin_unlock_irqrestore(&med->path_guard_lock, flags);
	hlist_for_each_entry_safe(entry, tmp, &entries, list) {
		hlist_del(&entry->list);
		kmem_cache_free(path_guard_cache, entry);
	}

	return 0;
}

/*
 * Check whether access to a @dentry from the @path is allowed or not. If a
 * dentry @new is not %NULL, it's the last element of the examined path.
 *
 * Returns 1 if the access is granted, 0 if the access is denied and a value
 * less than zero in the case of an error.
 */
int path_guard_check(struct dentry *dentry, const struct path *path,
		     struct dentry *new)
{
	struct inode *guarded_inode = d_backing_inode(dentry);
	struct path examined = *path;
	char *buf, *examined_path;
	int ret = 1;

	/* if inode has no protected paths defined, allow access */
	if (likely(!path_guard_has_entries(inode_security(guarded_inode))))
		return 1;

	buf = __getname();
	if (!buf) {
		med_pr_err("%s: OOM", __func__);
		return -ENOMEM;
	}

	if (new)
		examined.dentry = new;
	examined_path = d_absolute_path(&examined, buf, PATH_MAX);
	/* `d_absolute_path()` may return EINVAL or ENAMETOOLONG */
	if (IS_ERR(examined_path)) {
		ret = PTR_ERR(examined_path);
		med_pr_err("%s: d_absolute_path() failed with %d",
			   __func__, ret);
		goto out_path_guard;
	}
	if (!path_guard_path_is_allowed(examined_path,
					inode_security(guarded_inode))) {
		med_pr_info("%s: denied access from the path '%s'", __func__,
			    examined_path);
		ret = 0;
		goto out_path_guard;
	}
	med_pr_info("%s: access granted from the path '%s'", __func__,
		    examined_path);

out_path_guard:
	__putname(buf);
	return ret;
}

static struct medusa_kobject_s *path_guard_fetch(struct medusa_kobject_s *kobj)
{
	struct path_guard_kobject *guard = (struct path_guard_kobject *)kobj;
	struct inode *guarded_inode;
	struct path path;

	guard->path[sizeof(guard->path) - 1] = '\0';
	if (kern_path(guard->path, LOOKUP_FOLLOW, &path) < 0)
		return NULL;

	guarded_inode = d_backing_inode(path.dentry);
	guard->ino = guarded_inode->i_ino;
	guard->dev = new_encode_dev(guarded_inode->i_sb->s_dev);
	memset(guard->action, '\0', sizeof(guard->action));
	path_put(&path);

	return (struct medusa_kobject_s *)kobj;
}

/**
 * path_guard_update - update the allowed paths for an inode
 * @kobj: path_guard_kobject containing dev, ino, path, and action
 *
 * Add or remove @kobj's path for the file identified by its device and inode.
 * The action is either "append" or "remove".
 *
 * Return: %MED_ALLOW after a successful update or a no-op removal. Return
 * %MED_ERR if the inode cannot be found, the action is invalid, hashing fails,
 * or memory allocation fails.
 */
static enum medusa_answer_t path_guard_update(struct medusa_kobject_s *kobj)
{
	struct path_guard_kobject *guard = (struct path_guard_kobject *)kobj;
	struct super_block *sb;
	struct inode *guarded_inode;

	sb = user_get_super(new_decode_dev(guard->dev), false);
	if (!sb) {
		med_pr_warn("device %d not found", guard->dev);
		return MED_ERR;
	}
	guarded_inode = ilookup(sb, guard->ino);
	drop_super(sb);

	if (!guarded_inode) {
		med_pr_warn("inode %ld on dev %d not found in the cache",
			    guard->ino, guard->dev);
		return MED_ERR;
	}

	guard->path[sizeof(guard->path) - 1] = '\0';
	if (!strcmp(guard->action, "append")) {
		if (!path_guard_path_add(guard->path,
					 inode_security(guarded_inode))) {
			med_pr_warn("%s: OOM ino %ld dev %d", __func__,
				    guard->ino, guard->dev);
			iput(guarded_inode);
			return MED_ERR;
		}
	} else if (!strcmp(guard->action, "remove")) {
		/* removing non-existing path from allowed paths is silently ignored */
		path_guard_path_remove(guard->path,
				       inode_security(guarded_inode));
	} else {
		med_pr_warn("%s: invalid action '%s'", __func__,
			    guard->action);
		iput(guarded_inode);
		return MED_ERR;
	}

	med_pr_info("%s: '%s' (dev = %u, ino = %lu, act = %s)", __func__,
		    guard->path, guard->dev, guard->ino, guard->action);

	iput(guarded_inode);
	return MED_ALLOW;
}

MED_KCLASS(path_guard_kobject) {
	MEDUSA_KCLASS_HEADER(path_guard_kobject),
	"path_guard",
	NULL,		/* init kclass */
	NULL,		/* destroy kclass */
	path_guard_fetch,
	path_guard_update,
	NULL,		/* unmonitor */
};

static int __init path_guard_kobject_init(void)
{
	int error;

	hash_transformation = crypto_alloc_shash(PATH_GUARD_HASH_NAME, 0, 0);
	if (IS_ERR(hash_transformation)) {
		error = PTR_ERR(hash_transformation);
		hash_transformation = NULL;
		med_pr_err("%s: can't alloc %s during init, error: %d\n",
			   __func__, PATH_GUARD_HASH_NAME,
			   error);
		return error;
	}

	path_guard_cache = kmem_cache_create("medusa_path_guard",
					     sizeof(struct path_guard_entry), 0,
					     SLAB_HWCACHE_ALIGN | SLAB_PANIC,
					     NULL);
	if (!path_guard_cache) {
		error = -ENOMEM;
		med_pr_err("%s: can't allocate path_guard cache, error: %d",
			   __func__,
			   error);
		crypto_free_shash(hash_transformation);
		hash_transformation = NULL;
		return error;
	}

	MED_REGISTER_KCLASS(path_guard_kobject);
	return 0;
}

late_initcall(path_guard_kobject_init);

// SPDX-License-Identifier: GPL-2.0

#include "l3/arch.h"
#include "l3/registry.h"
#include "l3/med_cache.h"

/* nesting as follows: registry_lock is outer, usecount_lock is inner. */

DEFINE_MUTEX(registry_lock); /* the linked list lock */
static DEFINE_MUTEX(usecount_lock); /* the lock for modifying use-count */

static struct medusa_kclass_s *kclasses;
static struct medusa_evtype_s *evtypes;
static struct medusa_authserver_s *authserver;

int medusa_authserver_magic = 1; /* the 'version' of authserver */
/* WARNING! medusa_authserver_magic is not locked, nor atomic type,
 * because we want to have as much portable (and easy and fast) code
 * as possible. thus we must change its value BEFORE modifying authserver,
 * and place some memory barrier between, or get lock there - the lock
 * hopefully contains some kind of such barrier ;).
 */

/**
 * med_get_kclass - lock the kclass by incrementing its use-count.
 * @med_kclass: pointer to the kclass to lock
 *
 * This increments the use-count; works great even if you want to sleep.
 * when calling this function, the use-count must already be non-zero.
 */
void med_get_kclass(struct medusa_kclass_s *med_kclass)
{
	mutex_lock(&usecount_lock);
	med_kclass->use_count++;
	mutex_unlock(&usecount_lock);
}

/**
 * med_put_kclass - unlock the kclass by decrementing its use-count.
 * @med_kclass: pointer to the kclass to unlock
 *
 * This decrements the use-count. Note that it does nothing special when
 * the use-count goes to zero. Someone still may find the kclass in the
 * linked list and claim it by using med_get_kclass.
 */
void med_put_kclass(struct medusa_kclass_s *med_kclass)
{
	mutex_lock(&usecount_lock);
	if (med_kclass->use_count > 0) /* sanity check only */
		med_kclass->use_count--;
	mutex_unlock(&usecount_lock);
}

/**
 * med_get_kclass_by_pointer - find a kclass and return get-kclassed refference.
 * @med_kclass: unsafe pointer to the kclass to find
 *
 * It may return NULL on failure; caller must verify this each time.
 */
struct medusa_kclass_s *med_get_kclass_by_pointer(struct medusa_kclass_s *med_kclass)
{
	struct medusa_kclass_s *tmp;

	mutex_lock(&registry_lock);
	for (tmp = kclasses; tmp; tmp = tmp->next)
		if (med_kclass == tmp) {
			med_get_kclass(med_kclass);
			break;
		}
	mutex_unlock(&registry_lock);
	return tmp;
}

static inline int _med_unlink_kclass(struct medusa_kclass_s *med_kclass)
{
	struct medusa_kclass_s *pos, *prev;

	if (med_kclass == kclasses) {
		kclasses = med_kclass->next;
		return 0;
	}

	for (prev = kclasses, pos = kclasses->next; pos != NULL; prev = pos, pos = pos->next) {
		if (pos == med_kclass) {
			prev->next = pos->next;
			return 0;
		}
	}

	med_pr_devel("Failed to unlink kclass '%s' - not found", med_kclass->name);
	return -1;
}

/**
 * med_unlink_kclass - unlink the kclass from all L3 lists
 * @med_kclass: kclass to unlink
 *
 * This is called with use-count=0 to remove the kclass from L3
 * lists. It may be called with all kinds of locks held, and thus
 * it does not notify the authserver.
 *
 * That is: if the authserver really relies on the kclass, it should use
 * med_get_kclass() at the very beginning.
 *
 * If the use-count is nonzero, it fails gracefully. This allows use of
 * med_unlink_kclass as an atomic uninstallation check & unlink. Always
 * check the return value of this call.
 *
 * After returning from this function, some servers might still use
 * the kclass, but they must be able to give it up on del_kclass callback.
 * No new servers and/or event types will be able to attach to the kclass,
 * and it waits for its final deletion by med_unregister_kclass().
 *
 * callers, who call med_unlink_kclass and get MED_ALLOW, should really call
 * med_unregister_kclass soon.
 */
int med_unlink_kclass(struct medusa_kclass_s *med_kclass)
{
	int retval = -1;

	mutex_lock(&registry_lock);
	mutex_lock(&usecount_lock);
	if (med_kclass->use_count == 0) {
		retval = _med_unlink_kclass(med_kclass);
		if (retval != -1)
			med_kclass->next = NULL;
	}

	mutex_unlock(&usecount_lock);
	mutex_unlock(&registry_lock);
	return retval;
}

/**
 * med_unregister_kclass - unregister the kclass.
 *
 * This is called after the usage-count has dropped to 0, and also
 * after someone has called med_unlink_kclass. Its whole purpose is to
 * notify few routines about disappearance of kclass. They must accept
 * it and stop using the kclass, because after returning from this
 * function, the k-kclass does not exist.
 *
 * The callbacks called from here may sleep.
 */
int med_unregister_kclass(struct medusa_kclass_s *med_kclass)
{
	med_pr_info("Unregistering kclass %s\n", med_kclass->name);
	mutex_lock(&registry_lock);
	mutex_lock(&usecount_lock);
	if (med_kclass->use_count > 0 || med_kclass->next) { /* useless sanity check */
		char *err_str1 = "A fatal ERROR has occured; expect system crash.";
		char *err_str2 = "If you're removing a file-related kclass, press reset.";
		char *err_str3 = "Otherwise save now.";

		med_pr_crit("%s %s %s\n", err_str1, err_str2, err_str3);
		mutex_unlock(&usecount_lock);
		mutex_unlock(&registry_lock);
		return -1;
	}
	mutex_unlock(&usecount_lock);
	mutex_unlock(&registry_lock);
	if (authserver && authserver->del_kclass)
		authserver->del_kclass(med_kclass);
	/* FIXME: this isn't safe. add use-count to authserver too... */
	return 0;
}

/**
 * med_register_kclass - register a kclass of k-objects and notify the authserver
 * @med_kclass: pointer to the kclass to register
 *
 * The authserver call must be in lock or a semaphore - we promised
 * that in authserver.h. :)
 */
int med_register_kclass(struct medusa_kclass_s *med_kclass)
{
	struct medusa_kclass_s *p;

	med_kclass->name[MEDUSA_KCLASSNAME_MAX-1] = '\0';
	med_pr_info("Registering kclass %s\n", med_kclass->name);

	/* Register kmem cache for L4. */
	med_cache_register(med_kclass->kobject_size);

	mutex_lock(&registry_lock);
	for (p = kclasses; p; p = p->next)
		if (strcmp(p->name, med_kclass->name) == 0) {
			med_pr_err("Error: '%s' kclass already exists.\n", med_kclass->name);
			mutex_unlock(&registry_lock);
			return -1;
		}
	/* we don't write-lock usecount_lock. That's OK, because noone is
	 * able to find the entry before it's in the linked list.
	 * we set use-count to 1, and decrement it soon hereafter.
	 */
	med_kclass->use_count = 1;
	med_kclass->next = kclasses;
	kclasses = med_kclass;
	mutex_unlock(&registry_lock);
	if (authserver && authserver->add_kclass)
		authserver->add_kclass(med_kclass); /* TODO: some day, check the return value */
	med_put_kclass(med_kclass);
	return 0;
}

/**
 * med_register_evtype - register an event type and notify the authserver.
 * @med_evtype: pointer to the event type to register
 *
 * The event type must be prepared by l2 routines to contain pointers to
 * all related kclasses of k-objects.
 */
int med_register_evtype(struct medusa_evtype_s *med_evtype, int flags)
{
	struct medusa_evtype_s *p;

	med_evtype->name[MEDUSA_EVNAME_MAX-1] = '\0';
	med_evtype->arg_name[0][MEDUSA_ATTRNAME_MAX-1] = '\0';
	med_evtype->arg_name[1][MEDUSA_ATTRNAME_MAX-1] = '\0';
	/* TODO: check whether kclasses are registered, maybe register automatically */
	med_pr_info("Registering event type %s(%s:%s->%s:%s)\n", med_evtype->name,
		    med_evtype->arg_name[0], med_evtype->arg_kclass[0]->name,
		    med_evtype->arg_name[1], med_evtype->arg_kclass[1]->name);
	mutex_lock(&registry_lock);
	for (p = evtypes; p; p = p->next)
		if (strcmp(p->name, med_evtype->name) == 0) {
			mutex_unlock(&registry_lock);
			med_pr_err("Error: '%s' event type already exists.\n", med_evtype->name);
			return -1;
		}

	med_evtype->next = evtypes;
	med_evtype->bitnr = flags;

#define MASK (~(MEDUSA_EVTYPE_TRIGGEREDATOBJECT | MEDUSA_EVTYPE_TRIGGEREDATSUBJECT))
	if ((flags & MASK_BITNR) != MEDUSA_EVTYPE_NOTTRIGGERED) {
		for (p = evtypes; p; p ? (p = p->next) : (p = evtypes)) {
			if (p->bitnr != MEDUSA_EVTYPE_NOTTRIGGERED &&
			    (p->bitnr & MASK) == (med_evtype->bitnr & MASK)) {
				med_evtype->bitnr++;
				p = NULL;
				continue;
			}
		}
#undef MASK
		if ((med_evtype->bitnr & MASK_BITNR) >= CONFIG_MEDUSA_ACT) {
			mutex_unlock(&registry_lock);
			med_pr_err("%s(%s): bitnr %u >= %u (CONFIG_MEDUSA_ACT)",
				   __func__, med_evtype->name,
				   med_evtype->bitnr & MASK_BITNR,
				   CONFIG_MEDUSA_ACT);
			return -2;
		}
	}

	evtypes = med_evtype;
	if (authserver && authserver->add_evtype)
		authserver->add_evtype(med_evtype); /* TODO: some day, check for response */
	mutex_unlock(&registry_lock);
	return 0;
}

/**
 * med_unregister_evtype - unregister an event type and notify the authserver.
 * @med_evtype: pointer to the event type to unregister
 * FIXME - this is not used anywhere
 */
void med_unregister_evtype(struct medusa_evtype_s *med_evtype)
{
	struct medusa_evtype_s *tmp;

	med_pr_info("Unregistering event type %s\n", med_evtype->name);
	mutex_lock(&registry_lock);
	if (med_evtype == evtypes) {
		evtypes = med_evtype->next;
		mutex_unlock(&registry_lock);
		return;
	}

	for (tmp = evtypes; tmp; tmp = tmp->next) {
		if (tmp->next == med_evtype) {
			tmp->next = tmp->next->next;
			if (authserver && authserver->del_evtype)
				authserver->del_evtype(med_evtype);
			break;
		}
	}
	/* TODO: verify whether we found it */
	mutex_unlock(&registry_lock);
}

/**
 * med_register_authserver - register the authorization server
 * @med_authserver: pointer to the filled medusa_authserver_s structure
 *
 * This routine inserts the authorization server in the internal data
 * structures, sets the use-count to 1 (i.e. returns get-servered entry),
 * and announces all known classes to the server.
 */
int med_register_authserver(struct medusa_authserver_s *med_authserver)
{
	struct medusa_kclass_s *cp;
	struct medusa_evtype_s *ap;

	med_pr_info("Registering authorization server %s\n", med_authserver->name);
	mutex_lock(&registry_lock);
	if (authserver) {
		med_pr_err("Failed registration of auth. server '%s', reason: '%s' already present!\n", med_authserver->name, authserver->name);
		mutex_unlock(&registry_lock);
		return -1;
	}
	/* we don't write-lock usecount_lock. That's OK, because noone is
	 * able to find the entry before it's in the linked list.
	 * we set use-count to 1, and somebody has to decrement it some day.
	 */
	med_authserver->use_count = 1;
	medusa_authserver_magic++;
	authserver = med_authserver;

	/* we must remain in write-lock here, to synchronize add_*
	 * events across our code.
	 */
	if (med_authserver->add_kclass)
		for (cp = kclasses; cp; cp = cp->next)
			med_authserver->add_kclass(cp); /* TODO: some day we might want to check the return value, to support specialized servers */
	if (med_authserver->add_evtype)
		for (ap = evtypes; ap; ap = ap->next)
			med_authserver->add_evtype(ap); /* TODO: the same for this */

	mutex_unlock(&registry_lock);
	return 0;
}

/**
 * med_unregister_authserver - unlink the auth. server from L3.
 * @med_authserver: pointer to the server to unlink.
 *
 * This function is called by L4 code to unregister the auth. server.
 * After it has returned, no new questions will be placed to the server.
 * Note that some old questions might be pending, and after calling this,
 * it is wise to wait for close() callback to proceed with uninstallation.
 */
void med_unregister_authserver(struct medusa_authserver_s *med_authserver)
{
	med_pr_info("Unregistering authserver %s\n", med_authserver->name);
	mutex_lock(&registry_lock);
	/* the following code is a little bit useless, but we keep it here
	 * to allow multiple different authentication servers some day
	 */
	if (med_authserver != authserver) {
		mutex_unlock(&registry_lock);
		return;
	}
	medusa_authserver_magic++;
	authserver = NULL;
	mutex_unlock(&registry_lock);
	med_put_authserver(med_authserver);
}

/**
 * med_get_authserver - lock the authserver by increasing its use-count.
 *
 * This function gets one more refference to the authserver. Use it,
 * when you want to be sure the authserver won't vanish.
 */
struct medusa_authserver_s *med_get_authserver(void)
{
	mutex_lock(&usecount_lock);
	if (authserver) {
		authserver->use_count++;
		mutex_unlock(&usecount_lock);
		return authserver;
	}
	mutex_unlock(&usecount_lock);
	return NULL;
}

/**
 * med_put_authserver - release the authserver by decrementing its use-count
 * @med_authserver: a pointer to the authserver
 *
 * This is an opposite function to med_get_authserver. Please, try to call
 * this without any locks; the close() callback of L4 server, which may
 * eventually get called from here, may block. This might change, if
 * reasonable.
 */
void med_put_authserver(struct medusa_authserver_s *med_authserver)
{
	mutex_lock(&usecount_lock);
	if (med_authserver->use_count) /* sanity check only */
		med_authserver->use_count--;
	if (med_authserver->use_count) { /* fast path */
		mutex_unlock(&usecount_lock);
		return;
	}
	mutex_unlock(&usecount_lock);
	if (med_authserver->close)
		med_authserver->close();
}

/**
 * med_is_authserver_present - information about authserver.
 *
 * Returns true, if the authserver is connected in the moment of calling this
 * function, false otherwise.
 */
inline bool med_is_authserver_present(void)
{
	return !!authserver;
}

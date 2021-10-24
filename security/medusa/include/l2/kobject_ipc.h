// SPDX-License-Identifier: GPL-2.0

#ifndef _IPC_KOBJECT_H
#define _IPC_KOBJECT_H

#include "l3/kobject.h"
#include "l1/ipc.h"

/*
 * medusa_ipc_perm - struct holding relevant entries from 'kern_ipc_perm' (see linux/ipc.h)
 */
struct medusa_ipc_perm {
	bool	deleted;	/* helper to sort out IPC_RMID races */
	int	id;		/* IPC object id based on seq number */
	key_t	key;		/* IPC V identifier; key supplied to semget() */
	kuid_t	uid;		/* effective UID of owner */
	kgid_t	gid;		/* effective GID of owner */
	kuid_t	cuid;		/* effective UID of creator */
	kgid_t	cgid;		/* effective GID of creator */
	umode_t	mode;		/* permissions */
	unsigned long	seq;	/* sequence number used to generate IPC id */
	refcount_t refcount;	/* count of in-use references to IPC object */
};

/**
 * ipc_kobject - kobject structure for System V IPC: sem, msg, shm
 *
 * @ipc_class - type of System V IPC (sem, or msg, or shm)
 * @ipc_perm - copy of relevant entries from kernel IPC permission structure
 */
struct ipc_kobject {
	unsigned int ipc_class;
	struct medusa_ipc_perm ipc_perm;
	struct medusa_object_s med_object;
};
extern MED_DECLARE_KCLASSOF(ipc_kobject);

struct medusa_kobject_s * ipc_fetch(struct medusa_kobject_s *);
enum medusa_answer_t ipc_update(struct medusa_kobject_s * kobj);

struct ipc_kobject * ipc_kern2kobj(struct ipc_kobject *, struct kern_ipc_perm *, bool);
int ipc_getref(struct kern_ipc_perm *ipcp, bool unlock);
int ipc_putref(struct kern_ipc_perm *ipcp, bool lock);

#endif

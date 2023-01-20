/* SPDX-License-Identifier: GPL-2.0 */

/* (C) 2018 Viliam Mihalik
 *
 * IPC struct extension: this structure is appended to in-kernel data,
 * and we define it separately just to make l1 code shorter.
 *
 * for another data structure - kobject, describing ipc for upper layers -
 * see l2/ipc_kobject.[ch].
 */

#ifndef _MEDUSA_L1_IPC_H
#define _MEDUSA_L1_IPC_H

#include <linux/ipc.h>
#include <linux/lsm_hooks.h>
#include "l3/med_model.h"
#include "l3/constants.h"

/**
 * types of System V IPC objects
 */
#define MED_IPC_SEM 0	/* Semaphore */
#define MED_IPC_MSG 1	/* Message */
#define MED_IPC_SHM 2	/* Shared memory */
#define MED_IPC_UNDEFINED 3

/**
 * access to IPC Medusa security context
 */
extern struct lsm_blob_sizes medusa_blob_sizes;
#define ipc_security(ipc) ((struct medusa_l1_ipc_s *)(ipc->security + medusa_blob_sizes.lbs_ipc))

/**
 * struct medusa_l1_ipc_s - security struct for System V IPC objects (sem, msg, shm)
 *
 * @ipc_class - medusa_l1_ipc_s is stored in 'struct kern_ipc_perm' of each System V object,
 *	so we need store extra information about IPC type in 'ipc_class' struct member
 * @struct med_object - members used in Medusa VS access evaluation process
 */
struct medusa_l1_ipc_s {
	unsigned int ipc_class;	/* type of a System V IPC object */
	struct medusa_object_s med_object;
};

extern int medusa_ipc_permission(struct kern_ipc_perm *ipcp, short flag);
extern int medusa_ipc_ctl(struct kern_ipc_perm *ipcp, int cmd, char *operation);
extern int medusa_ipc_associate(struct kern_ipc_perm *ipcp, int flag, char *operation);
extern int medusa_ipc_semop(struct kern_ipc_perm *ipcp, struct sembuf *sops, unsigned int nsops, int alter);
extern int medusa_ipc_shmat(struct kern_ipc_perm *ipcp, char __user *shmaddr, int shmflg);
extern int medusa_ipc_msgsnd(struct kern_ipc_perm *ipcp, struct msg_msg *msg, int msgflg);
extern int medusa_ipc_msgrcv(struct kern_ipc_perm *ipcp, struct msg_msg *msg, struct task_struct *target, long type, int mode);
extern int medusa_queue_associate(struct kern_ipc_perm *ipcp, int flag);
extern int medusa_shm_associate(struct kern_ipc_perm *ipcp, int flag);
extern int medusa_sem_associate(struct kern_ipc_perm *ipcp, int flag);
extern int medusa_queue_ctl(struct kern_ipc_perm *ipcp, int cmd);
extern int medusa_shm_ctl(struct kern_ipc_perm *ipcp, int cmd);
extern int medusa_sem_ctl(struct kern_ipc_perm *ipcp, int cmd);

/*
 * The following routine makes a support for many of access types,
 * and it is used both in L1 and L2 code. It is defined in
 * l2/evtype_getipc.c.
 */
extern enum medusa_answer_t ipc_kobj_validate_ipcp(struct kern_ipc_perm *ipcp);

#endif // _MEDUSA_L1_IPC_H

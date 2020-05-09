#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l2/audit_medusa.h>
#include <linux/medusa/l1/task.h>
#include <linux/medusa/l1/ipc.h>
#include <linux/lsm_audit.h>
#include <linux/init.h>
#include <linux/mm.h>
#include "kobject_process.h"
#include "kobject_ipc.h"

struct ipc_semop_access {
	MEDUSA_ACCESS_HEADER;
	/* sem_num, sem_op and sem_flg are from sembuf struct definition;
	   see include/uapi/linux/sem.h */
	unsigned int sem_num;	/* semaphore index in array */
	int sem_op;		/* semaphore operation */
	int sem_flg;		/* operation flags */
	unsigned int nsops;	/* number of operations to perform */
	int alter;		/* indicates whether changes on semaphore array are to be made */
	unsigned int ipc_class;
};

MED_ATTRS(ipc_semop_access) {
	MED_ATTR_RO (ipc_semop_access, sem_num, "sem_num", MED_UNSIGNED),
	MED_ATTR_RO (ipc_semop_access, sem_op, "sem_op", MED_SIGNED),
	MED_ATTR_RO (ipc_semop_access, sem_flg, "sem_flg", MED_SIGNED),
	MED_ATTR_RO (ipc_semop_access, nsops, "nsops", MED_UNSIGNED),
	MED_ATTR_RO (ipc_semop_access, alter, "alter", MED_SIGNED),
	MED_ATTR_RO (ipc_semop_access, ipc_class, "ipc_class", MED_UNSIGNED),
	MED_ATTR_END
};

MED_ACCTYPE(ipc_semop_access, "ipc_semop", process_kobject, "process", ipc_kobject, "object");

int __init ipc_acctype_semop_init(void) {
	MED_REGISTER_ACCTYPE(ipc_semop_access,MEDUSA_ACCTYPE_TRIGGEREDATOBJECT);
	return 0;
}

static void medusa_ipc_semop_pacb(struct audit_buffer *ab, void *pcad);
/*
 * Check permissions before performing operations on members of the semaphore set
 * @ipcp contains semaphore ipc_perm structure
 * @sops contains the operation to perform
 * @nsops contains the number of operations to perform
 * @alter contains the flag indicating whether changes are to be made;
 *	if @alter flag is nonzero, the semaphore set may be modified
 *
 * This routine is called only by do_semtimedop() (ipc/sem.c) in RCU read-side.
 *
 * security_sem_semop()
 *  |
 *  |<-- do_semtimedop()
 */
medusa_answer_t medusa_ipc_semop(struct kern_ipc_perm *ipcp, struct sembuf *sops, unsigned nsops, int alter)
{
	medusa_answer_t retval = MED_ALLOW;
	struct common_audit_data cad;
	struct medusa_audit_data mad = { .event = EVENT_MONITORED_N, .pacb.ipc_semop.ipc_class = MED_IPC_UNDEFINED };
	struct ipc_semop_access access;
	struct process_kobject process;
	struct ipc_kobject object;

	/* second argument false: don't need to unlock IPC object */
	if (unlikely(ipc_getref(ipcp, false)))
		/* for now, we don't support error codes */
		return MED_DENY;
	if (!is_med_magic_valid(&(task_security(current)->med_object)) && process_kobj_validate_task(current) <= 0)
		goto out;
	if (!is_med_magic_valid(&(ipc_security(ipcp)->med_object)) && ipc_kobj_validate_ipcp(ipcp) <= 0)
		goto out;

	cad.type = LSM_AUDIT_DATA_IPC;
	cad.u.ipc_id = ipcp->key;

	if (MEDUSA_MONITORED_ACCESS_S(ipc_semop_access, task_security(current))) {
		mad.event = EVENT_MONITORED;
		process_kern2kobj(&process, current);
		/* 3-th argument is true: decrement IPC object's refcount in returned object */
		if (ipc_kern2kobj(&object, ipcp, true) == NULL)
			goto audit;

		memset(&access, '\0', sizeof(struct ipc_semop_access));
		access.sem_op = sops->sem_op;
		access.sem_num = sops->sem_num;
		access.sem_flg = sops->sem_flg;
		access.nsops = nsops;
		access.alter = alter;
		access.ipc_class = object.ipc_class;
		mad.pacb.ipc_semop.ipc_class = object.ipc_class;

		retval = MED_DECIDE(ipc_semop_access, &access, &process, &object);
		if (retval == MED_ERR)
			retval = MED_ALLOW;
	}
audit:
	if (unlikely(ipc_putref(ipcp, false)))
		retval = MED_DENY;
#ifdef CONFIG_AUDIT
	mad.function = __func__;
	mad.med_answer = retval;
	mad.pacb.ipc_semop.sem_num = sops->sem_num;
	mad.pacb.ipc_semop.sem_op = sops->sem_op;
	mad.pacb.ipc_semop.sem_flg = sops->sem_flg;
	mad.pacb.ipc_semop.nsops = nsops;
	mad.pacb.ipc_semop.alter = alter;
	cad.medusa_audit_data = &mad;
	medusa_audit_log_callback(&cad, medusa_ipc_semop_pacb);
#endif
	return retval;
out:
	/* second argument false: don't need to lock IPC object */
	if (unlikely(ipc_putref(ipcp, false)))
		/* for now, we don't support error codes */
		retval = MED_DENY;
	return retval;
}

static void medusa_ipc_semop_pacb(struct audit_buffer *ab, void *pcad)
{
	struct common_audit_data *cad = pcad;
	struct medusa_audit_data *mad = cad->medusa_audit_data;

	if ((&(mad->pacb.ipc_semop))->sem_flg) {
		audit_log_format(ab," flag=%d",((&(mad->pacb.ipc_semop))->sem_flg));
	}
	if ((&(mad->pacb.ipc_semop))->sem_num) {
		audit_log_format(ab," sem_num=%u",((&(mad->pacb.ipc_semop))->sem_num));
	}
	if ((&(mad->pacb.ipc_semop))->sem_op) {
		audit_log_format(ab," sem_op=%d",((&(mad->pacb.ipc_semop))->sem_op));
	}
	if ((&(mad->pacb.ipc_semop))->nsops) {
		audit_log_format(ab," nsops=%u",((&(mad->pacb.ipc_semop))->nsops));
	}
	if ((&(mad->pacb.ipc_semop))->alter) {
		audit_log_format(ab," alter=%d",((&(mad->pacb.ipc_semop))->alter));
	}
	if ((&(mad->pacb.ipc_semop))->ipc_class) {
		audit_log_format(ab," ipc_class=%u",((&(mad->pacb.ipc_semop))->ipc_class));
	}
}
__initcall(ipc_acctype_semop_init);

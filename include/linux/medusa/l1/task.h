/* medusa/l1/inode.h, (C) 2002 Milan Pikula
 *
 * task-struct extension: this structure is appended to in-kernel data,
 * and we define it separately just to make l1 code shorter.
 *
 * for another data structure - kobject, describing task for upper layers -
 * see l2/kobject_process.[ch].
 */

#ifndef _MEDUSA_L1_TASK_H
#define _MEDUSA_L1_TASK_H

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/sched/task.h>
#include <linux/kernel.h>
#include <asm/syscall.h>
#include <linux/sys.h>
#include <linux/lsm_hooks.h>
#include <linux/medusa/l3/med_model.h>

extern struct lsm_blob_sizes medusa_blob_sizes;
#define task_security(task) ((struct medusa_l1_task_s *)(task->security + medusa_blob_sizes.lbs_task))

struct medusa_l1_task_s {
	kuid_t luid;
	struct medusa_subject_s med_subject;
	struct medusa_object_s med_object;
        char cmdline[128];
#ifdef CONFIG_MEDUSA_FORCE
	void *force_code;       /* code to force or NULL, kfree */
	int force_len;          /* force code length */
#endif /* CONFIG_MEDUSA_FORCE */
#if (defined(CONFIG_X86) || defined(CONFIG_X86_64)) && defined(CONFIG_MEDUSA_SYSCALL)
	/* FIXME: we only watch linux syscalls. Not only that's not good,
	 * but I am not sure whether NR_syscalls is enough on non-x86 archs.
	 * If you know how to write this correctly, mail to www@terminus.sk,
	 * thanks :).
	 */
	/* bitmap of syscalls, which are reported */
	unsigned char med_syscall[NR_syscalls / (sizeof(unsigned char) * 8)];
#endif
};

#endif

/* SPDX-License-Identifier: GPL-2.0 */

/* (C) 2002 Milan Pikula
 *
 * task-struct extension: this structure is appended to in-kernel data,
 * and we define it separately just to make l1 code shorter.
 *
 * for another data structure - kobject, describing task for upper layers -
 * see l2/kobject_process.[ch].
 */

#ifndef _MEDUSA_L1_TASK_H
#define _MEDUSA_L1_TASK_H

#include <linux/lsm_hooks.h>
#include "l3/med_model.h"
#include "l3/constants.h"

/* prototypes of L2 process related handlers called from L1 hooks */

extern enum medusa_answer_t medusa_setresuid(uid_t ruid, uid_t euid, uid_t suid);
extern enum medusa_answer_t medusa_capable(int cap);
extern enum medusa_answer_t medusa_fork(unsigned long clone_flags);
extern enum medusa_answer_t medusa_init_process(struct task_struct *new);
extern enum medusa_answer_t medusa_sendsig(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred);
extern enum medusa_answer_t medusa_afterexec(char *filename, char **argv, char **envp);
extern int medusa_monitored_pexec(void);
extern void medusa_monitor_pexec(int flag);
extern int medusa_monitored_afterexec(void);
extern void medusa_monitor_afterexec(int flag);
extern enum medusa_answer_t medusa_sexec(struct linux_binprm *bprm);
extern enum medusa_answer_t medusa_ptrace(struct task_struct *tracer, struct task_struct *tracee);
extern void medusa_kernel_thread(int (*fn)(void *));

extern int process_kobj_validate_task(struct task_struct *ts);

/* Struct task extension: this structure is appended to in-kernel data,
 * and we define it separately just to make l1 code shorter.
 */

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
#ifdef CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL
	struct rcu_head rcu;	/* rcu head for delayed_put_task_struct() cb registration */
	struct task_struct *self; /* ptr to task struct related to this task security blob */
	refcount_t rcu_cb_set; /* 1 if rcu delayed_put_task_struct() cb is set */
#endif /* CONFIG_SECURITY_MEDUSA_HOOKS_TASK_KILL */
	struct mutex validation_in_progress;
	int validation_depth_nesting;
};

#endif

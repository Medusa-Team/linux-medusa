// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2002 by Milan Pikula
 *
 * Fixes:
 * Matus Jokay : - rewrite kobj2kern and kern2kobj functionality
 *               - add code documentation
 *               matus.jokay@gmail.com
 * Roderik Ploszek: - formatting and minor touch-ups
 *                  roderik.ploszek@gmail.com
 */

#include "l3/registry.h"
#include "l2/kobject_process.h"

/**
 * uid_differs() - Check equality of original and new (proposed) UID.
 * @newid:         New (proposed) UID from authorization server.
 * @old:           Original (actual) UID of the task's credentials.
 * @type:          Description of UID type; one of "real", "effective",
 *                 "saved", "filesystem", "login".
 * @cmd:           Task's command line.
 * @pid:           Task's pid.
 * @print_warning: If set to True, warning message in some scenario can
 *                 be printed (see below).
 *
 * Compare value of actual task's credentials @old with value @newid from
 * authorization server. If they are equal, return true. Otherwise return
 * false.
 *
 * Input variable @newid is an integer, so it has to be converted to &typedef
 * kuid_t type. Value is converted into a global kernel uid namespace (i.e. init
 * namespace) instead of a process one. If a result of this mapping is an
 * invalid uid and @print_warning is set to True, a warning message is printed.
 */
static inline bool uid_differs(int newid, kuid_t old,
			       char *type, char *cmd, pid_t pid,
			       bool print_warning)
{
	kuid_t new = make_kuid(&init_user_ns, newid);

	if (!uid_eq(new, old)) {
		if (!uid_valid(new) && print_warning)
			med_pr_warn("Invalid %s UID %d for task '%s' (PID %u)\n",
					type, newid, cmd, pid);
		return true;
	}
	return false;
}

/**
 * gid_differs() - Check equality of original and new (proposed) GID.
 * @newid:         New (proposed) GID from authorization server.
 * @old:           Original (actual) GID of the task's credentials.
 * @type:          Description of GID type; one of "real", "effective",
 *                 "saved", "filesystem".
 * @cmd:           Task's command line.
 * @pid:           Task's pid.
 * @print_warning: If set to True, warning message in some scenario can be
 *                 printed (see below).
 *
 * Compare value of actual task's credentials @old with value @newid from
 * authorization server. If they are equal, return true. Otherwise return false.
 *
 * Input variable @newid is an integer, so it has to be converted to &typedef
 * kgid_t type. Value is converted into a global kernel gid namespace (i.e. init
 * namespace) instead of a process one. If a result of this mapping is an
 * invalid gid and @print_warning is set to True, a warning message is printed.
 */
static inline bool gid_differs(int newid, kgid_t old,
			       char *type, char *cmd, pid_t pid,
			       bool print_warning)
{
	kgid_t new = make_kgid(&init_user_ns, newid);

	if (!gid_eq(new, old)) {
		if (!gid_valid(new) && print_warning)
			med_pr_warn("Invalid %s GID %d for task '%s' (PID %u)\n",
					type, newid, cmd, pid);
		return true;
	}
	return false;
}

/**
 * process_kobj2kern() - Make conversion from a kobject to a kernel struct.
 * @tk: Input kobject of a process.
 * @ts: Output task_struct of a process.
 *
 * Make change(s) on process's &struct task_struct @ts based on information
 * obtained from authorization server in kobject @tk. It's called only from
 * *update* operation of the authorization server.
 *
 * Note: A task may only alter its *own* credentials; it is never permitted for
 *       a task to alter another's credentials. So the program code manipulating
 *       with task's credentials is never reached. It is ready as an example of
 *       the intention (POC). As a consequence, function never fails (return
 *       -ENOMEM is never reached).
 *
 * This routine expects:
 * 1) existing task security blob within an @ts (this is ensured by LSM itself)
 * 2) not %NULL @tk (this is the responsibility of a Medusa's programmer)
 *
 * Return: 0 on success, -ENOMEM on failure (see Note above).
 */
static int process_kobj2kern(struct process_kobject *tk, struct task_struct *ts)
{
	struct cred *new;
	const struct cred *old;
	struct medusa_l1_task_s *ts_security = task_security(ts);
	bool change_cred = false;
#ifdef CONFIG_AUDIT
	bool change_luid = false;
#endif

	/* Save variable information stored in Medusa security context */
	ts_security->med_subject = tk->med_subject;
	ts_security->med_object = tk->med_object;
#if (defined(CONFIG_X86) || defined(CONFIG_X86_64)) && defined(CONFIG_MEDUSA_SYSCALL)
	memcpy(ts_security->med_syscall, tk->med_syscall, sizeof(ts_security->med_syscall));
#endif

	/* Check an attempt of the credential's information modification */
	rcu_read_lock();
	/* TODO Access a task's objective credentials, should be subjective */
	old = __task_cred(ts);
	change_cred |= uid_differs(tk->uid, old->uid, "real", ts->comm, ts->pid, true);
	change_cred |= uid_differs(tk->euid, old->euid, "effective", ts->comm, ts->pid, true);
	change_cred |= uid_differs(tk->suid, old->suid, "saved", ts->comm, ts->pid, true);
	change_cred |= uid_differs(tk->fsuid, old->fsuid, "filesystem", ts->comm, ts->pid, true);
	change_cred |= gid_differs(tk->gid, old->gid, "real", ts->comm, ts->pid, true);
	change_cred |= gid_differs(tk->egid, old->egid, "effective", ts->comm, ts->pid, true);
	change_cred |= gid_differs(tk->sgid, old->sgid, "saved", ts->comm, ts->pid, true);
	change_cred |= gid_differs(tk->fsgid, old->fsgid, "filesystem", ts->comm, ts->pid, true);
#ifdef CONFIG_AUDIT
	change_luid = uid_differs(tk->luid, ts->loginuid, "login", ts->comm, ts->pid, true);
	if (change_luid)
		ts->loginuid = make_kuid(&init_user_ns, tk->luid);
#endif
	rcu_read_unlock();

	ts_security->audit = tk->audit;

	/* If no change of credentials is requested, return */
	if (!change_cred)
		goto out;

	/* An attempt to modify task's credentials */
	#warning FIXME - permit a task to alter (subjective) credentials of an (another) task

	if (current->pid != ts->pid) {
		/*
		 * A task may only alter its *own* credentials; it is no longer permitted for
		 * a task to alter another's credentials! There is no mechanism for doing it
		 * in the kernel.
		 */
		med_pr_warn("An attempt of task '%s' %u to alter credentials of the task '%s' %u\n",
				current->comm, current->pid, ts->comm, ts->pid);

		/* As we can't change another task's credentials, there is nothing to do anymore */
		goto out;
	}

	/* With Constable never reached until not fixed modification of task's credentials */
	med_pr_warn("Task '%s' %u modifies credentials of itself\n",
			current->comm, current->pid);

	/* Make a working copy of *current* task's objective credentials */
	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	/* Change information about user (UID) */
	if (!uid_eq(task_uid(ts), make_kuid(&init_user_ns, tk->uid))) {
		/* Copied from sys.c: set_user() */
		struct user_struct *new_user;

		new_user = alloc_uid(make_kuid(&init_user_ns, tk->uid));
		if (!new_user) {
			abort_creds(new);
			return -ENOMEM;
		}
		free_uid(new->user);
		new->user = new_user;
		new->uid = make_kuid(&init_user_ns, tk->uid);
	}

	/* Replace remaining (E/S/FS)IDs */
	new->euid = make_kuid(&init_user_ns, tk->euid);
	new->suid = make_kuid(&init_user_ns, tk->suid);
	new->fsuid = make_kuid(&init_user_ns, tk->fsuid);

	/* Replace all GIDs */
	new->gid = make_kgid(&init_user_ns, tk->gid);
	new->egid = make_kgid(&init_user_ns, tk->egid);
	new->sgid = make_kgid(&init_user_ns, tk->sgid);
	new->fsgid = make_kgid(&init_user_ns, tk->fsgid);

	/* Replace capabilities */
	new->cap_effective = tk->ecap;
	new->cap_inheritable = tk->icap;
	new->cap_permitted = tk->pcap;
	new->cap_bset = tk->bcap;
	new->cap_ambient = tk->acap;

	/* Replace both subjective and objective current task's credentials */
	commit_creds(new);

out:
	/* validate security context of the process */
	med_magic_validate(&(ts_security->med_object));
	return 0;
}

/**
 * process_kern2kobj() - Make conversion from a kernel struct to a kobject.
 * @tk: Output kobject of a process.
 * @ts: Input task_struct of a process.
 *
 * Copy information about process (stored in &struct task_struct @ts) for
 * authorization server (kobject @tk). This function is called from: 1) *fetch*
 * operation of the authorization server, 2) from process_kobj_validate_task(),
 * 3) from each acctype which subject/object/attribute is a process.
 *
 * This routine expects:
 * 1) existing task security blob within an @ts (this is ensured by LSM itself)
 * 2) not %NULL @tk (this is the responsibility of a Medusa's programmer)
 *
 * Note: The kernel api permits secure access only to objective context of
 *       another task. Almost always the objective and subjective contexts are
 *       the same. So for now, the function gets information about the objective
 *       context of a given task.
 *
 * Return: 0 (success)
 */
inline int process_kern2kobj(struct process_kobject *tk, struct task_struct *ts)
{
	struct medusa_l1_task_s *ts_security = task_security(ts);
	const struct cred *cred;
	struct task_struct *task;

	memset(tk, '\0', sizeof(struct process_kobject));

	tk->audit = ts_security->audit;

	rcu_read_lock();

	/* Copy information from task_struct itself */

	tk->pid = ts->pid;
	/* Take pids from global (i.e. init) namespace */
	tk->pgrp = pid_nr(task_pgrp(ts));
	tk->tgid = pid_nr(task_tgid(ts));
	tk->session = pid_nr(task_session(ts));

	task = rcu_dereference(ts->real_parent);
	if (task)
		tk->parent_pid = task->pid;
	task = (struct task_struct *)(ts->children.next);
	if (task)
		tk->child_pid = task->pid;
	task = (struct task_struct *)(ts->sibling.next);
	if (task)
		tk->sibling_pid = task->pid;
#ifdef CONFIG_AUDIT
	tk->luid = from_kuid(&init_user_ns, ts->loginuid);
#endif

	/* Information from security context */

	tk->med_subject = ts_security->med_subject;
	tk->med_object = ts_security->med_object;
	memcpy(tk->cmdline, ts_security->cmdline, sizeof(tk->cmdline));
#if (defined(CONFIG_X86) || defined(CONFIG_X86_64)) && defined(CONFIG_MEDUSA_SYSCALL)
	memcpy(tk->med_syscall, ts_security->med_syscall, sizeof(tk->med_syscall));
#endif

	/* TODO Access a task's objective credentials, should be subjective */

	cred = __task_cred(ts);
	tk->uid = from_kuid(&init_user_ns, cred->uid);
	tk->euid = from_kuid(&init_user_ns, cred->euid);
	tk->suid = from_kuid(&init_user_ns, cred->suid);
	tk->fsuid = from_kuid(&init_user_ns, cred->fsuid);
	tk->gid = from_kgid(&init_user_ns, cred->gid);
	tk->egid = from_kgid(&init_user_ns, cred->egid);
	tk->sgid = from_kgid(&init_user_ns, cred->sgid);
	tk->fsgid = from_kgid(&init_user_ns, cred->fsgid);

	tk->ecap = cred->cap_effective;
	tk->icap = cred->cap_inheritable;
	tk->pcap = cred->cap_permitted;
	tk->acap = cred->cap_ambient;
	tk->bcap = cred->cap_bset;

	rcu_read_unlock();

	return 0;
}

/*
 * Follows description of @process_kobject structure for l4.
 */
MED_ATTRS(process_kobject) {
	MED_ATTR_KEY_RO(process_kobject, pid, "pid", MED_SIGNED),
	MED_ATTR_RO(process_kobject, pgrp, "pgrp", MED_SIGNED),
	MED_ATTR_RO(process_kobject, tgid, "tgid", MED_SIGNED),
	MED_ATTR_RO(process_kobject, session, "session", MED_SIGNED),
	MED_ATTR_RO(process_kobject, parent_pid, "parent_pid", MED_SIGNED),
	MED_ATTR_RO(process_kobject, child_pid, "child_pid", MED_SIGNED),
	MED_ATTR_RO(process_kobject, sibling_pid, "sibling_pid", MED_SIGNED),
	MED_ATTR_RO(process_kobject, cmdline, "cmdline", MED_STRING),
	MED_ATTR(process_kobject, uid, "uid", MED_UNSIGNED),
	MED_ATTR(process_kobject, euid, "euid", MED_UNSIGNED),
	MED_ATTR(process_kobject, suid, "suid", MED_UNSIGNED),
	MED_ATTR(process_kobject, fsuid, "fsuid", MED_UNSIGNED),
	MED_ATTR(process_kobject, gid, "gid", MED_UNSIGNED),
	MED_ATTR(process_kobject, egid, "egid", MED_UNSIGNED),
	MED_ATTR(process_kobject, sgid, "sgid", MED_UNSIGNED),
	MED_ATTR(process_kobject, fsgid, "fsgid", MED_UNSIGNED),
	MED_ATTR(process_kobject, ecap, "ecap", MED_BITMAP | MED_LE),
	MED_ATTR(process_kobject, icap, "icap", MED_BITMAP | MED_LE),
	MED_ATTR(process_kobject, pcap, "pcap", MED_BITMAP | MED_LE),
	MED_ATTR(process_kobject, bcap, "bcap", MED_BITMAP | MED_LE),
	MED_ATTR(process_kobject, acap, "acap", MED_BITMAP | MED_LE),
#ifdef CONFIG_AUDIT
	MED_ATTR(process_kobject, luid, "luid", MED_UNSIGNED),
#endif
	MED_ATTR_SUBJECT(process_kobject),
	MED_ATTR_OBJECT(process_kobject),
#if (defined(CONFIG_X86) || defined(CONFIG_X86_64)) && defined(CONFIG_MEDUSA_SYSCALL)
	MED_ATTR(process_kobject, med_syscall, "syscall", MED_BYTES),
#endif
	MED_ATTR(process_kobject, audit, "audit", MED_SIGNED),
	MED_ATTR_END
};

/**
 * process_fetch() - Fetch operation of the authorization server on the process.
 * @kobj: Output process information storage.
 *
 * Routine gets information about a process and stores them info @kobj. It is
 * called from an authorization server as a remote procedure, so the information
 * about a process are sent back to the server.
 *
 * Return: NULL on error, address of output storage otherwise.
 */
static struct medusa_kobject_s *process_fetch(struct medusa_kobject_s *kobj)
{
	struct task_struct *p;
	struct medusa_kobject_s *retval = NULL;

	rcu_read_lock();
	/* Find task_struct based on pid in global (i.e. init) namespace */
	p = find_task_by_pid_ns(((struct process_kobject *)kobj)->pid, &init_pid_ns);
	if (!p)
		goto out_err_fetch;

	retval = kobj;
	process_kern2kobj((struct process_kobject *)kobj, p);

out_err_fetch:
	rcu_read_unlock();
	return retval;
}

/**
 * process_update() - Modify a kernel object based on info from auth server.
 * @kobj: Input process information storage to read from.
 *
 * Routine modifies state of the appropriate process @kobj. It is called from an
 * authorization server as a remote procedure to modify/update state of a
 * process (which PID is stored in @kobj).
 *
 * Return: value < 0 on error, zero otherwise.
 */
static enum medusa_answer_t process_update(struct medusa_kobject_s *kobj)
{
	struct task_struct *p;
	enum medusa_answer_t retval = MED_ERR;

	if (!kobj)
		return MED_ERR;

	rcu_read_lock();
	/* Find task_struct based on pid in global (i.e. init) namespace */
	p = find_task_by_pid_ns(((struct process_kobject *)kobj)->pid, &init_pid_ns);
	if (!p)
		goto out_err_update;

	/* process_kobj2kern can return an error value */
	retval = MED_ALLOW;
	if (unlikely(process_kobj2kern((struct process_kobject *)kobj, p) < 0))
		retval = MED_ERR;

out_err_update:
	rcu_read_unlock();
	return retval;
}

/**
 * process_unmonitor() - take a process away from the security policy.
 * @kobj: Input process information storage to read PID from it.
 *
 * Routine removes a process from monitoring by authorization server.
 */
static void process_unmonitor(struct medusa_kobject_s *kobj)
{
	struct task_struct *p;

	rcu_read_lock();
	/* Find task_struct based on pid in global (i.e. init) namespace */
	p = find_task_by_pid_ns(((struct process_kobject *)kobj)->pid, &init_pid_ns);
	if (p) {
		unmonitor_med_object(&(task_security(p)->med_object));
		unmonitor_med_subject(&(task_security(p)->med_subject));
		med_magic_validate(&(task_security(p)->med_object));
	}
	rcu_read_unlock();
}

/*
 * Follows definition of process_kobject kclass for purpose of l3.
 */
MED_KCLASS(process_kobject) {
	MEDUSA_KCLASS_HEADER(process_kobject),
	"process",
	NULL,
	NULL,
	process_fetch,
	process_update,
	process_unmonitor,
};

/**
 * process_kobject_init() - Init function of the module.
 */
int __init process_kobject_init(void)
{
	MED_REGISTER_KCLASS(process_kobject);
	return 0;
}

/* Voila, we're done. */
device_initcall(process_kobject_init);

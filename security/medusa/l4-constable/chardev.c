// SPDX-License-Identifier: GPL-2.0

/*
 * L4 authorization server for Medusa DS9
 * Copyright (C) 2002 Milan Pikula <www@terminus.sk>, all rights reserved.
 *
 * This program comes with both BSD and GNU GPL v2 licenses. Check the
 * documentation for more information.
 *
 *
 * This server communicates with an user-space
 * authorization daemon, using a character device
 *
 *	  /dev/medusa c 111 0		on Linux
 *	  /dev/medusa c 90 0		on NetBSD
 */

/* define this if you want fatal protocol errors to cause segfault of
 * auth. daemon. Note that issuing strange read(), write(), or trying
 * to access the character device multiple times at once is not considered
 * a protocol error. This triggers only if we REALLY get some junk from the
 * user-space.
 */
#define ERRORS_CAUSE_SEGFAULT

/* define this to support workaround of decisions for named process. This
 * is especially useful when using GDB on constable.
 */
#define GDB_HACK

/* TODO: Check the calls to l3; they can't be called from a lock. */
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/sched/signal.h>
#include <linux/device.h>
#include <linux/poll.h>
#include <linux/preempt.h>
#include <linux/rwsem.h>
#include <linux/unaligned.h>
#include <linux/mm.h>

#include "l1/task.h"
#include "l3/arch.h"
#include "l3/health.h"
#include "l3/registry.h"
#include "l3/server.h"
#include "l3/med_cache.h"
#include "l3/pending.h"
#include "l3/protocol_stats.h"
#include "l4/auth_server.h"
#include "l4/comm.h"
#include "l4/protocol.h"
#include "l4/teleport.h"

#define MEDUSA_MAJOR 111
#define MODULENAME "chardev/linux"

static int user_release(struct inode *inode, struct file *file);

static struct teleport_s teleport = {
	.cycle = tpc_HALT,
};

/* constable, our brave userspace daemon */
static atomic_t constable_present = ATOMIC_INIT(0);
static struct medusa_server_health constable_health =
	MEDUSA_SERVER_HEALTH_INIT;
static struct task_struct *constable;
static struct task_struct *gdb;
static DEFINE_SEMAPHORE(constable_openclose, 1);


/* fetch or update answer */
static atomic_t fetch_requests = ATOMIC_INIT(0);
static atomic_t update_requests = ATOMIC_INIT(0);

/* to-register queue for constable */
static DEFINE_MUTEX(registration_lock);
/* the following two are circular lists, they have to be global
 * because of put operations in user_close()
 */
static struct medusa_kclass_s *kclasses_registered;
static struct medusa_evtype_s *evtypes_registered;
static atomic_t announce_ready = ATOMIC_INIT(0);

/* a question from kernel to constable */
static atomic_t questions = ATOMIC_INIT(0);
static atomic_t questions_waiting = ATOMIC_INIT(0);

static DECLARE_WAIT_QUEUE_HEAD(close_wait);

static DECLARE_WAIT_QUEUE_HEAD(userspace_chardev);
static struct semaphore user_read_lock;
static struct semaphore queue_items;
static struct semaphore queue_lock;
static LIST_HEAD(tele_queue);
struct tele_item {
	struct teleport_insn_s *tele;
	struct list_head list;
	size_t size;
	void (*post)(void *arg);
};

// Next three variables are used by user_open. They are here because we have to
// free the underlying data structures and clear them in user_close.
static size_t left_in_teleport;
static struct tele_item *local_list_item;
static struct teleport_insn_s *processed_teleport;

static DECLARE_RWSEM(lightswitch);

#ifdef GDB_HACK
static pid_t gdb_pid = -1;
//MODULE_PARM(gdb_pid, "i");
//MODULE_PARM_DESC(gdb_pid, "PID to exclude from monitoring");
#endif

/*******************************************************************************
 * kernel-space interface
 */

static enum medusa_answer_t l4_decide(struct medusa_event_s *event,
		struct medusa_kobject_s *o1,
		struct medusa_kobject_s *o2,
		struct medusa_authserver_decision *decision);
static int l4_add_kclass(struct medusa_kclass_s *cl);
static int l4_add_evtype(struct medusa_evtype_s *at);
static void l4_close_wake(void);
static bool l4_is_healthy(void);
static enum medusa_health_reason l4_health_reason(void);

static struct medusa_authserver_s chardev_medusa = {
	.name = MODULENAME,
	.close = l4_close_wake,
	.add_kclass = l4_add_kclass,
	.add_evtype = l4_add_evtype,
	.decide = l4_decide,
	.is_healthy = l4_is_healthy,
	.health_reason = l4_health_reason,
};

/*
 * Used to clean up data structures after fetch or update.
 */
static void post_write(void *mem)
{
	if (((struct teleport_insn_s *)mem)[1].args.put32.what == MEDUSA_COMM_FETCH_ANSWER)
		med_cache_free(((struct teleport_insn_s *)mem)[4].args.cutnpaste.from);
	med_cache_free(mem);
}

static int am_i_constable(void)
{
	if (!constable)
		return 0;

	rcu_read_lock();
	if (task_tgid(current) == task_tgid(constable)) {
		rcu_read_unlock();
		return 1;
	}
	rcu_read_unlock();

	return 0;
}

static bool l4_cannot_wait(void)
{
	if (!in_task() || preempt_count() || irqs_disabled())
		return true;
#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
	if (current->non_block_count)
		return true;
#endif
	return false;
}

static bool l4_is_healthy(void)
{
	return medusa_server_health_is_healthy(&constable_health);
}

static enum medusa_health_reason l4_health_reason(void)
{
	return medusa_server_health_reason(&constable_health);
}

static void l4_mark_unhealthy(enum medusa_health_reason reason)
{
	if (medusa_server_health_mark_unhealthy(&constable_health, reason))
		med_pr_warn("authorization server circuit breaker opened, reason=%d\n",
			    reason);

	/*
	 * Wake every slow-path caller so each event can apply its own installed
	 * fallback. New calls are rejected by is_healthy().
	 */
	medusa_pending_request_cancel_all(MED_ERR);
	wake_up_all(&userspace_chardev);
}

static void l4_record_protocol_error(enum medusa_protocol_counter counter,
				     bool command_present, u64 command,
				     bool request_present, u64 request_id,
				     int error)
{
	struct medusa_protocol_error_context context = {
		.counter = counter,
		.policy_generation =
			(u64)READ_ONCE(medusa_authserver_magic),
		.command = command,
		.request_id = request_id,
		.error = error,
		.command_present = command_present,
		.request_present = request_present,
	};

	medusa_protocol_record_error(&context);
}

static void l4_record_request_error(u64 command, u64 request_id, int error)
{
	if (error == -ENOENT)
		l4_record_protocol_error(MEDUSA_PROTOCOL_UNKNOWN_REQUESTS,
					 true, command, true, request_id, error);
	else if (error == -ESTALE)
		l4_record_protocol_error(MEDUSA_PROTOCOL_STALE_REQUESTS,
					 true, command, true, request_id, error);
}

static void l4_record_malformed_message(bool command_present, u64 command)
{
	l4_record_protocol_error(MEDUSA_PROTOCOL_MALFORMED_MESSAGES,
				 command_present, command, false, 0, -EMSGSIZE);
}

static void l4_close_wake(void)
{
	wake_up(&close_wait);
}

static int l4_add_kclass(struct medusa_kclass_s *cl)
{
	struct teleport_insn_s *tele_mem_kclass;
	struct tele_item *local_tele_item;
	int attr_num = 1;
	struct medusa_attribute_s *attr_ptr;

	tele_mem_kclass = (struct teleport_insn_s *)
		med_cache_alloc_size(sizeof(struct teleport_insn_s) * 5);
	if (!tele_mem_kclass)
		return -ENOMEM;
	local_tele_item = (struct tele_item *)
		med_cache_alloc_size(sizeof(struct tele_item));
	if (!local_tele_item) {
		med_cache_free(tele_mem_kclass);
		return -ENOMEM;
	}

	med_get_kclass(cl); // put is in user_release

	mutex_lock(&registration_lock);
	atomic_inc(&announce_ready);

	cl->cinfo = (void *)kclasses_registered;
	kclasses_registered = cl;
	local_tele_item->size = 0;
	tele_mem_kclass[0].opcode = tp_PUTPtr;
	tele_mem_kclass[0].args.putPtr.what = 0;
	local_tele_item->size += sizeof(MCPptr_t);
	tele_mem_kclass[1].opcode = tp_PUT32;
	tele_mem_kclass[1].args.put32.what =
		MEDUSA_COMM_KCLASSDEF;
	local_tele_item->size += sizeof(uint32_t);
	tele_mem_kclass[2].opcode = tp_PUTKCLASS;
	tele_mem_kclass[2].args.putkclass.kclassdef = cl;
	local_tele_item->size += sizeof(struct medusa_comm_kclass_s);
	tele_mem_kclass[3].opcode = tp_PUTATTRS;
	tele_mem_kclass[3].args.putattrs.attrlist = cl->attr;
	attr_ptr = cl->attr;
	while (attr_ptr->type != MED_END) {
		attr_num++;
		attr_ptr++;
	}
	local_tele_item->size += attr_num * sizeof(struct medusa_comm_attribute_s);
	tele_mem_kclass[4].opcode = tp_HALT;
	local_tele_item->tele = tele_mem_kclass;
	local_tele_item->post = med_cache_free;
	down(&queue_lock);
	list_add_tail(&local_tele_item->list, &tele_queue);
	up(&queue_lock);
	up(&queue_items);
	wake_up(&userspace_chardev);
	mutex_unlock(&registration_lock);
	return 0;
}

static int l4_add_evtype(struct medusa_evtype_s *at)
{
	struct teleport_insn_s *tele_mem_evtype;
	struct tele_item *local_tele_item;
	int attr_num = 1;
	struct medusa_attribute_s *attr_ptr;

	med_pr_debug("%s: adding %s with bitnr=%d\n", __func__, at->name,
		at->bitnr & MASK_BITNR);

	tele_mem_evtype = (struct teleport_insn_s *)
		med_cache_alloc_size(sizeof(struct teleport_insn_s)*5);
	if (!tele_mem_evtype)
		return -ENOMEM;
	local_tele_item = (struct tele_item *)
		med_cache_alloc_size(sizeof(struct tele_item));
	if (!local_tele_item) {
		med_cache_free(tele_mem_evtype);
		return -ENOMEM;
	}

	mutex_lock(&registration_lock);
	atomic_inc(&announce_ready);

	at->cinfo = (void *)evtypes_registered;
	evtypes_registered = at;
	local_tele_item->size = 0;
	tele_mem_evtype[0].opcode = tp_PUTPtr;
	tele_mem_evtype[0].args.putPtr.what = 0;
	local_tele_item->size += sizeof(MCPptr_t);
	tele_mem_evtype[1].opcode = tp_PUT32;
	tele_mem_evtype[1].args.put32.what =
		MEDUSA_COMM_EVTYPEDEF;
	local_tele_item->size += sizeof(uint32_t);
	tele_mem_evtype[2].opcode = tp_PUTEVTYPE;
	tele_mem_evtype[2].args.putevtype.evtypedef = at;
	local_tele_item->size += sizeof(struct medusa_comm_evtype_s);
	tele_mem_evtype[3].opcode = tp_PUTATTRS;
	tele_mem_evtype[3].args.putattrs.attrlist = at->attr;
	attr_ptr = at->attr;
	while (attr_ptr->type != MED_END) {
		attr_num++;
		attr_ptr++;
	}
	local_tele_item->size += attr_num * sizeof(struct medusa_comm_attribute_s);
	tele_mem_evtype[4].opcode = tp_HALT;
	local_tele_item->tele = tele_mem_evtype;
	local_tele_item->post = med_cache_free;
	down(&queue_lock);
	list_add_tail(&local_tele_item->list, &tele_queue);
	up(&queue_lock);
	up(&queue_items);
	wake_up(&userspace_chardev);
	mutex_unlock(&registration_lock);
	return 0;
}

/* the sad fact about this routine is that it sleeps...
 *
 * guess what? we can FULLY solve that silly problem on SMP,
 * eating one processor by a constable... ;) One can imagine
 * the performance improvement, and buy one more CPU in advance :)
 */
static enum medusa_answer_t l4_decide(struct medusa_event_s *event,
		struct medusa_kobject_s *o1, struct medusa_kobject_s *o2,
		struct medusa_authserver_decision *decision)
{
	enum medusa_answer_t retval;
	struct medusa_pending_request pending;
	struct teleport_insn_s *tele_mem_decide;
	struct tele_item *local_tele_item;
	char debug_cmdline[1024];
	u64 policy_generation;
	int error;

	decision->request_id = 0;
	decision->policy_generation =
		(u64)READ_ONCE(medusa_authserver_magic);
	decision->unavailable = MEDUSA_AUTH_SERVER_UNREACHABLE;
	decision->request_present = false;
	decision->contacted = false;

	/*
	 * A userspace decision blocks.  Some legacy hooks can reach this layer
	 * while preemption or interrupts are disabled, especially SysV IPC on
	 * UP kernels where a non-debug spinlock has no inspectable owner.
	 * Refuse the slow path here rather than scheduling from atomic context.
	 * The decision engine will eventually resolve MED_ERR through the
	 * installed kernel baseline policy.
	 */
	if (l4_cannot_wait()) {
		decision->unavailable = MEDUSA_NON_SLEEPABLE_CONTEXT;
		med_pr_warn_ratelimited("%s: cannot delegate '%s' from non-sleepable context\n",
				       __func__, event->evtype_id->name);
		return MED_ERR;
	}
	if (am_i_constable() || current == gdb)
		return MED_ALLOW;

	if (current->pid < 1)
		return MED_ERR;
#ifdef GDB_HACK
	if (gdb_pid == current->pid)
		return MED_ALLOW;
#endif
	tele_mem_decide = (struct teleport_insn_s *)
		med_cache_alloc_size(sizeof(struct teleport_insn_s)*6);
	if (!tele_mem_decide)
		return MED_ERR;

	local_tele_item = (struct tele_item *)
		med_cache_alloc_size(sizeof(struct tele_item));
	if (!local_tele_item) {
		med_cache_free(tele_mem_decide);
		return MED_ERR;
	}
	local_tele_item->tele = tele_mem_decide;
	local_tele_item->size = 0;
	local_tele_item->post = med_cache_free;

	/*
	 * We might be called with the IPC ids->rwsem held (from IPC security
	 * hooks) and lightswitch should always nest inside the ids->rwsem one.
	 * Attention: authorization server must NOT use IPC subsystem at all to
	 * ========== avoid deadlock (trying to lock ids->rwsem inside the
	 *            lightswitch)!.
	 */
	down_read_nested(&lightswitch, SINGLE_DEPTH_NESTING);

	policy_generation = (u64)READ_ONCE(medusa_authserver_magic);
	error = medusa_pending_request_register(&pending, policy_generation);
	if (error) {
		med_cache_free(tele_mem_decide);
		med_cache_free(local_tele_item);
		up_read(&lightswitch);
		med_pr_err("%s: pending request error: %d\n", __func__, error);
		if (error == -ENOSPC)
			l4_mark_unhealthy(MEDUSA_HEALTH_OVERLOADED);
		if (error == -ENOSPC)
			decision->unavailable = MEDUSA_AUTH_SERVER_OVERLOADED;
		return MED_ERR;
	}
	decision->request_id = pending.id;
	decision->policy_generation = pending.policy_generation;
	decision->request_present = true;

#define decision_evtype (event->evtype_id)
	tele_mem_decide[0].opcode = tp_PUTPtr;
	tele_mem_decide[0].args.putPtr.what = (MCPptr_t)decision_evtype; // possibility to encryption JK march 2015
	local_tele_item->size += sizeof(MCPptr_t);
	tele_mem_decide[1].opcode = tp_PUTPtr;
	tele_mem_decide[1].args.putPtr.what = (MCPptr_t)pending.id;
	local_tele_item->size += sizeof(MCPptr_t);
	tele_mem_decide[2].opcode = tp_CUTNPASTE;
	tele_mem_decide[2].args.cutnpaste.from = (unsigned char *)event;
	tele_mem_decide[2].args.cutnpaste.count = decision_evtype->event_size;
	local_tele_item->size += decision_evtype->event_size;
	tele_mem_decide[3].opcode = tp_CUTNPASTE;
	tele_mem_decide[3].args.cutnpaste.from = (unsigned char *)o1;
	tele_mem_decide[3].args.cutnpaste.count =
		decision_evtype->arg_kclass[0]->kobject_size;
	local_tele_item->size += decision_evtype->arg_kclass[0]->kobject_size;
	if (o1 == o2) {
		tele_mem_decide[4].opcode = tp_HALT;
	} else {
		tele_mem_decide[4].opcode = tp_CUTNPASTE;
		tele_mem_decide[4].args.cutnpaste.from =
			(unsigned char *)o2;
		tele_mem_decide[4].args.cutnpaste.count =
			decision_evtype->arg_kclass[1]->kobject_size;
		local_tele_item->size += decision_evtype->arg_kclass[1]->kobject_size;
		tele_mem_decide[5].opcode = tp_HALT;
	}

	/* TODO: Replace by constable tgid and move up right below lightswitch */
	if (!atomic_read(&constable_present)) {
		med_cache_free(local_tele_item);
		med_cache_free(tele_mem_decide);
		medusa_pending_request_unregister(&pending);
		up_read(&lightswitch);
		return MED_ERR;
	}

	debug_cmdline[0] = '\0';
	/* get_cmdline() is too expensive; uncomment it manually while debugging */
	//get_cmdline(current, debug_cmdline, 1023);
	//debug_cmdline[1023] = '\0';
	med_pr_debug("task pid %d ('%s'), new question 0x%llx for '%s'",
		     current->pid, debug_cmdline, pending.id,
		     decision_evtype->name);

#undef decision_evtype
	// insert teleport structure to the queue
	down(&queue_lock);
	list_add_tail(&local_tele_item->list, &tele_queue);
	up(&queue_lock);
	up(&queue_items);
	atomic_inc(&questions);

	up_read(&lightswitch);
	wake_up(&userspace_chardev);
	decision->contacted = true;
	error = medusa_pending_request_wait_timeout(
		&pending,
		msecs_to_jiffies(CONFIG_SECURITY_MEDUSA_DECISION_LEASE_MS),
		&retval);
	if (error == -ETIMEDOUT) {
		decision->unavailable = MEDUSA_DECISION_TIMED_OUT;
		l4_mark_unhealthy(MEDUSA_HEALTH_DECISION_TIMEOUT);
	}

	/*
	 * We might be called with the IPC ids->rwsem held (from IPC security
	 * hooks) and lightswitch should always nest inside the ids->rwsem one.
	 * Attention: authorization server must NOT use IPC subsystem at all to
	 * ========== avoid deadlock (trying to lock ids->rwsem inside the
	 *            lightswitch)!.
	 */
	down_read_nested(&lightswitch, SINGLE_DEPTH_NESTING);
	if (retval != MED_ERR && atomic_read(&constable_present) &&
	    policy_generation == (u64)READ_ONCE(medusa_authserver_magic))
		atomic_dec(&questions_waiting);
	if (retval != MED_ERR) {
		med_pr_debug("task pid %d, question 0x%llx answer %d",
			     current->pid, pending.id, retval);
	} else {
		med_pr_err("task pid %d, question 0x%llx for '%s' not answered, authorization server disconnected",
			   current->pid, pending.id, event->evtype_id->name);
	}
	up_read(&lightswitch);
	return retval;
}

/***********************************************************************
 * user-space interface
 */

static ssize_t user_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos);
static ssize_t user_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos);
static unsigned int user_poll(struct file *filp, poll_table *wait);
static int user_open(struct inode *inode, struct file *file);
static int user_release(struct inode *inode, struct file *file);

static const struct file_operations fops = {
	.read		= user_read,
	.write		= user_write,
	.llseek		= noop_llseek,
	.poll		= user_poll,
	.open		= user_open,
	.release	= user_release
	/* We don't support async IO. I have no idea, when to call kill_fasync
	 * to be correct. Only on decisions? Or also on answers to user-space
	 * questions? Not a big problem, though... noone seems to be supporting
	 * it anyway :). If you need it, let me know. <www@terminus.sk>
	 *
	 * Also, we don't like the ioctl() - we hope the character device can
	 * be used over the network.
	 */
};
/* TODO: userspace_buf is GLOBAL variable */
static char __user *userspace_buf;

static ssize_t to_user(void *from, size_t len)
{ /* we verify the access rights elsewhere */
	if (__copy_to_user(userspace_buf, from, len))
		;
	userspace_buf += len;
	return len;
}

static void decrement_counters(struct teleport_insn_s *tele)
{
	if (tele[1].opcode == tp_HALT)
		return;
	switch (tele[2].opcode) {
	case tp_CUTNPASTE: // Authorization server answer
		atomic_inc(&questions_waiting);
		atomic_dec(&questions);
		break;
	case tp_PUTPtr: // Fetch or update
		switch (tele[1].args.put32.what) {
		case MEDUSA_COMM_FETCH_ANSWER:
		case MEDUSA_COMM_FETCH_ERROR:
			atomic_dec(&fetch_requests);
			break;
		case MEDUSA_COMM_UPDATE_ANSWER:
			atomic_dec(&update_requests);
			break;
		}
		break;
	case tp_PUTKCLASS:
	case tp_PUTEVTYPE:
	case tp_PUTREADY:
		atomic_dec(&announce_ready);
		break;
	}
}

/*
 * trylock - if true, don't block
 * returns 1 if queue is empty, otherwise 0
 * returns -EPIPE if Constable was disconnected
 * while waiting for new event
 */
static inline int teleport_pop(int trylock)
{
	if (trylock) {
		if (down_trylock(&queue_items))
			return 1;
	} else {
		up_read(&lightswitch);
		while (down_timeout(&queue_items, 5*HZ) == -ETIME) {
			down_read(&lightswitch);
			if (!atomic_read(&constable_present))
				return -EPIPE;
			up_read(&lightswitch);
		}
		down_read(&lightswitch);
	}
	down(&queue_lock);
	local_list_item = list_first_entry(&tele_queue, struct tele_item, list);
	processed_teleport = local_list_item->tele;
	left_in_teleport = local_list_item->size;
	list_del(&(local_list_item->list));
	up(&queue_lock);
	teleport_reset(&teleport, &(processed_teleport[0]), to_user);
	decrement_counters(processed_teleport);
	return 0;
}

static inline void teleport_put(void)
{
	if (local_list_item->post)
		local_list_item->post(processed_teleport);
	med_cache_free(local_list_item);
	processed_teleport = NULL;
	local_list_item = NULL;
}

// Clear the teleport queue
static inline void teleport_clear(void)
{
	struct list_head *pos, *next;

	left_in_teleport = 0;
	if (local_list_item)
		teleport_put();
	down(&queue_lock);
	list_for_each_safe(pos, next, &tele_queue) {
		local_list_item = list_entry(pos, struct tele_item, list);
		processed_teleport = local_list_item->tele;
		list_del(&(local_list_item->list));
		teleport_put();
	}
	up(&queue_lock);
}

static int send_medusa_is_ready(void)
{
	struct teleport_insn_s *tele_mem;
	struct tele_item *local_tele_item;

	tele_mem = (struct teleport_insn_s *)
		med_cache_alloc_size(sizeof(struct teleport_insn_s) * 4);
	if (!tele_mem)
		return -ENOMEM;
	local_tele_item = (struct tele_item *)
		med_cache_alloc_size(sizeof(struct tele_item));
	if (!local_tele_item) {
		med_cache_free(tele_mem);
		return -ENOMEM;
	}

	atomic_inc(&announce_ready);
	local_tele_item->size = 0;
	tele_mem[0].opcode = tp_PUTPtr;
	tele_mem[0].args.putPtr.what = 0;
	local_tele_item->size += sizeof(MCPptr_t);
	tele_mem[1].opcode = tp_PUT32;
	tele_mem[1].args.put32.what = MEDUSA_COMM_READY_REQUEST;
	local_tele_item->size += sizeof(uint32_t);
	tele_mem[2].opcode = tp_PUTREADY; /* used only for decrement_counter() */
	tele_mem[3].opcode = tp_HALT;
	local_tele_item->tele = tele_mem;
	local_tele_item->post = med_cache_free;
	down(&queue_lock);
	list_add_tail(&local_tele_item->list, &tele_queue);
	up(&queue_lock);
	up(&queue_items);
	wake_up(&userspace_chardev);

	return 0;
}

/*
 * READ()
 */
static ssize_t user_read(struct file *filp, char __user *buf,
		size_t count, loff_t *ppos)
{
	ssize_t retval;
	size_t retval_sum = 0;

	// Lightswitch
	// has to be there: so close can't occur during read
	down_read(&lightswitch);

	if (!atomic_read(&constable_present)) {
		up_read(&lightswitch);
		return -EPIPE;
	}

	if (!am_i_constable()) {
		up_read(&lightswitch);
		return -EPERM;
	}
	if (*ppos != filp->f_pos) {
		up_read(&lightswitch);
		return -ESPIPE;
	}
	if (!access_ok(buf, count)) {
		up_read(&lightswitch);
		return -EFAULT;
	}

	// Lock it before someone can change the userspace_buf
	// Only one reader can use it
	down(&user_read_lock);
	userspace_buf = buf;
	// Get an item from the queue
	// Get a new item only if the previous teleport has been fully transported
	if (!left_in_teleport) {
		// Interruptible waiting; -EPIPE if auth server was disconnected
		if (teleport_pop(0) == -EPIPE) {
			up(&user_read_lock);
			up_read(&lightswitch);
			return -EPIPE;
		}
	}
	while (1) {
		retval = teleport_cycle(&teleport, count);
		if (retval < 0) { /* unexpected error; data lost */
			// this teleport was broken, we get rid of it
			left_in_teleport = 0;
			teleport_put();
			up(&user_read_lock);
			up_read(&lightswitch);
			return retval;
		}
		left_in_teleport -= retval;
		count -= retval;
		retval_sum += retval;
		if (!left_in_teleport) {
			// We can get rid of current teleport
			teleport_put();
			if (!count)
				break;
			// Userspace wants more data
			if (teleport_pop(1))
				break;
			// left in teleport will be always zero, because while loop in
			// teleport_reset loops while count is not zero until it encounters
			// tpc_HALT
		} else {
			// Something was left in teleport
			if (retval == 0 && teleport.cycle == tpc_HALT) {
				// Discard current teleport
				left_in_teleport = 0;
				teleport_put();
				// Get new teleport
				if (teleport_pop(0) == -EPIPE) {
					up(&user_read_lock);
					up_read(&lightswitch);
					return -EPIPE;
				}
				continue;
			}
			break;
		}
	} // while
	if (retval_sum > 0 || teleport.cycle != tpc_HALT) {
		up(&user_read_lock);
		up_read(&lightswitch);
		return retval_sum;
	}

	// Something is still in teleport, but we didn't transport any data
	up(&user_read_lock);
	up_read(&lightswitch);
	return 0;
}

/*
 * WRITE()
 */
static ssize_t user_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
	size_t orig_count = count;
	struct medusa_kclass_s *cl;
	struct teleport_insn_s *tele_mem_write;
	struct tele_item *local_tele_item;
	enum medusa_answer_t answ_result;
	MCPptr_t recv_type;
	MCPptr_t answ_kclassid = 0;
	struct medusa_kobject_s *answ_kobj = NULL;
	MCPptr_t answ_seq = 0;
	char recv_buf[sizeof(MCPptr_t)*2];
	char *kclass_buf;
	u64 id;
	u64 gen;
	s16 answer;

	// Lightswitch
	// has to be there so close can't occur during write
	down_read(&lightswitch);

	if (!atomic_read(&constable_present)) {
		up_read(&lightswitch);
		med_pr_err("write: constable not present\n");
		return -EPIPE;
	}

	if (!am_i_constable()) {
		up_read(&lightswitch);
		med_pr_err("write: not called by authorization server\n");
		return -EPERM;
	}
	if (*ppos != filp->f_pos) {
		up_read(&lightswitch);
		med_pr_err("write: incorrect file position\n");
		return -ESPIPE;
	}
	if (!access_ok(buf, count)) {
		up_read(&lightswitch);
		med_pr_err("write: can't read buffer\n");
		return -EFAULT;
	}
	if (count < sizeof(MCPptr_t)) {
		l4_record_malformed_message(false, 0);
		up_read(&lightswitch);
		return -EMSGSIZE;
	}

	if (__copy_from_user(((char *)&recv_type), buf,
				sizeof(MCPptr_t))) {
		up_read(&lightswitch);
		med_pr_err("write: can't copy buffer\n");
		return -EFAULT;
	}
	buf += sizeof(MCPptr_t);
	count -= sizeof(MCPptr_t);

	// Type of the message is received
	if (recv_type == MEDUSA_COMM_AUTHANSWER) {
		if (count != MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE) {
			l4_record_malformed_message(true, recv_type);
			up_read(&lightswitch);
			return -EMSGSIZE;
		}
		if (__copy_from_user(recv_buf, buf, sizeof(int16_t) + sizeof(MCPptr_t))) {
			up_read(&lightswitch);
			med_pr_err("write: can't copy buffer\n");
			return -EFAULT;
		}
		buf += sizeof(int16_t) + sizeof(MCPptr_t);
		count -= sizeof(int16_t) + sizeof(MCPptr_t);

		id = get_unaligned((u64 *)recv_buf);
		answer = get_unaligned((s16 *)(recv_buf + sizeof(MCPptr_t)));
		answ_result = medusa_comm_validate_authanswer(
			MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE,
			answer, true);
		if (answ_result == -EINVAL)
			l4_record_protocol_error(MEDUSA_PROTOCOL_INVALID_ANSWERS,
						 true, recv_type, true, id,
						 answ_result);
		if (!answ_result)
			gen =
				(u64)READ_ONCE(medusa_authserver_magic);
		if (!answ_result)
			answ_result = medusa_pending_request_complete(id, gen, answer);
		if (answ_result) {
			l4_record_request_error(recv_type, id, answ_result);
			up_read(&lightswitch);
			med_pr_err("decision_answer: invalid answer for request %llx: %d\n",
				   id, answ_result);
			return answ_result;
		}
		medusa_protocol_counter_inc(MEDUSA_PROTOCOL_REPLIES);
		med_pr_debug("answer received for %llx\n",
			     id);

	} else if (recv_type == MEDUSA_COMM_AUTHREQUEST_PROGRESS) {
		if (count != MEDUSA_COMM_AUTHREQUEST_PROGRESS_PAYLOAD_SIZE) {
			l4_record_malformed_message(true, recv_type);
			up_read(&lightswitch);
			return -EMSGSIZE;
		}
		if (__copy_from_user(recv_buf, buf, sizeof(MCPptr_t))) {
			up_read(&lightswitch);
			return -EFAULT;
		}

		id = get_unaligned((u64 *)recv_buf);
		gen = (u64)READ_ONCE(medusa_authserver_magic);
		answ_result = medusa_pending_request_renew(id, gen);
		if (answ_result) {
			l4_record_request_error(recv_type, id, answ_result);
			up_read(&lightswitch);
			med_pr_err("decision_progress: invalid request %llx: %d\n",
				   id, answ_result);
			return answ_result;
		}
		medusa_protocol_counter_inc(MEDUSA_PROTOCOL_LEASE_RENEWALS);
		med_pr_debug("decision lease renewed for %llx\n", id);

	} else if (recv_type == MEDUSA_COMM_FETCH_REQUEST ||
			recv_type == MEDUSA_COMM_UPDATE_REQUEST) {
		if (__copy_from_user(recv_buf, buf, sizeof(MCPptr_t)*2)) {
			up_read(&lightswitch);
			med_pr_err("write: can't copy buffer\n");
			return -EFAULT;
		}
		buf += sizeof(MCPptr_t)*2;
		count -= sizeof(MCPptr_t)*2;

		cl = med_get_kclass_by_pointer(
				*(struct medusa_kclass_s **)(recv_buf) // posibility to decrypt JK march 2015
				);
		if (!cl) {
			med_pr_err("Protocol error at write(): unknown kclass 0x%p!\n",
				(void *)(*(MCPptr_t *)(recv_buf)));
#ifdef ERRORS_CAUSE_SEGFAULT
			up_read(&lightswitch);
			return -EFAULT;
#else
			break;
#endif
		}
		kclass_buf = (char *) med_cache_alloc_size(cl->kobject_size);
		if (!kclass_buf) {
			up_read(&lightswitch);
			med_pr_err("write: OOM while `kclass_buf` alloc\n");
			return -ENOMEM;
		}
		if (__copy_from_user(kclass_buf, buf, cl->kobject_size)) {
			med_cache_free(kclass_buf);
			up_read(&lightswitch);
			med_pr_err("write: can't copy buffer\n");
			return -EFAULT;
		}
		buf += cl->kobject_size;
		count -= cl->kobject_size;

		// if (atomic_read(&fetch_requests) || atomic_read(&update_requests)) {
		//	/* not so much to do... */
		//	med_put_kclass(answ_kclass);
		//     // ked si to uzivatel precita, tak urob put - tam, kde sa rusi objekt
		// }

		answ_kclassid = (*(MCPptr_t *)(recv_buf));
		answ_seq = *(((MCPptr_t *)(recv_buf))+1);


		if (recv_type == MEDUSA_COMM_FETCH_REQUEST) {
			if (cl->fetch)
				answ_kobj = cl->fetch((struct medusa_kobject_s *)
						kclass_buf);
			else {
				answ_kobj = NULL;
				med_cache_free(kclass_buf);
			}
		} else {
			if (cl->update)
				answ_result = cl->update(
						(struct medusa_kobject_s *)kclass_buf);
			else
				answ_result = MED_ERR;
			med_cache_free(kclass_buf);
		}
		// Dynamic telemem structure for fetch/update
		tele_mem_write = (struct teleport_insn_s *) med_cache_alloc_size(sizeof(struct teleport_insn_s)*6);
		if (!tele_mem_write) {
			med_cache_free(kclass_buf);
			up_read(&lightswitch);
			med_pr_err("write: OOM while `tele_mem_write` alloc");
			return -ENOMEM;
		}
		local_tele_item = (struct tele_item *) med_cache_alloc_size(sizeof(struct tele_item));
		if (!local_tele_item) {
			med_cache_free(tele_mem_write);
			med_cache_free(kclass_buf);
			up_read(&lightswitch);
			med_pr_err("write: OOM while `local_tele_item` alloc");
			return -ENOMEM;
		}
		local_tele_item->size = 0;
		tele_mem_write[0].opcode = tp_PUTPtr;
		tele_mem_write[0].args.putPtr.what = 0;
		local_tele_item->size += sizeof(MCPptr_t);
		tele_mem_write[1].opcode = tp_PUT32;
		if (recv_type == MEDUSA_COMM_FETCH_REQUEST) { /* fetch */
			tele_mem_write[1].args.put32.what = answ_kobj ?
				MEDUSA_COMM_FETCH_ANSWER : MEDUSA_COMM_FETCH_ERROR;
		} else { /* update */
			tele_mem_write[1].args.put32.what = MEDUSA_COMM_UPDATE_ANSWER;
		}
		local_tele_item->size += sizeof(uint32_t);
		tele_mem_write[2].opcode = tp_PUTPtr;
		tele_mem_write[2].args.putPtr.what = (MCPptr_t)answ_kclassid;
		local_tele_item->size += sizeof(MCPptr_t);
		tele_mem_write[3].opcode = tp_PUTPtr;
		tele_mem_write[3].args.putPtr.what = (MCPptr_t)answ_seq;
		local_tele_item->size += sizeof(MCPptr_t);
		if (recv_type == MEDUSA_COMM_UPDATE_REQUEST) {
			//med_pr_debug("answering update %llu\n", answ_seq);
			tele_mem_write[4].opcode = tp_PUT32;
			tele_mem_write[4].args.put32.what = answ_result;
			local_tele_item->size += sizeof(uint32_t);
			tele_mem_write[5].opcode = tp_HALT;
		} else if (answ_kobj) {
			tele_mem_write[4].opcode = tp_CUTNPASTE;
			tele_mem_write[4].args.cutnpaste.from = (void *)answ_kobj;
			tele_mem_write[4].args.cutnpaste.count = cl->kobject_size;
			local_tele_item->size += cl->kobject_size;
			tele_mem_write[5].opcode = tp_HALT;
		} else
			tele_mem_write[4].opcode = tp_HALT;
		med_put_kclass(cl); /* slightly too soon */ /* TODO Find out what is this */
		local_tele_item->tele = tele_mem_write;
		local_tele_item->post = post_write;
		down(&queue_lock);
		list_add(&(local_tele_item->list), &tele_queue);
		up(&queue_lock);
		up(&queue_items);
		/*
		 * Increment counters right after inserting data into teleport
		 * to avoid data processing if they are not ready yet: authserver
		 * can be woken up from another parts of this module, too.
		 */
		if (recv_type == MEDUSA_COMM_FETCH_REQUEST) /* fetch */
			atomic_inc(&fetch_requests);
		else /* update */
			atomic_inc(&update_requests);
		wake_up(&userspace_chardev);
	} else if (recv_type == MEDUSA_COMM_READY_ANSWER) {
		/* register auth server */
		medusa_server_health_mark_healthy(&constable_health);
		if (med_register_authserver(&chardev_medusa) < 0) {
			medusa_server_health_mark_unhealthy(
				&constable_health, MEDUSA_HEALTH_DISCONNECTED);
			med_pr_warn("Failed to register auth server: "
				    "no decision request will be send to it!");
			up_read(&lightswitch);
			return -EPERM;
		}
		med_pr_info("authorization server circuit breaker closed\n");
		set_auth_server_ready();
		} else {
			l4_record_protocol_error(MEDUSA_PROTOCOL_UNKNOWN_COMMANDS,
						 true, recv_type, false, 0,
						 -EOPNOTSUPP);
			med_pr_err("Protocol error at write(): unknown command %llx!\n",
				   recv_type);
#ifdef ERRORS_CAUSE_SEGFAULT
		up_read(&lightswitch);
		return -EFAULT;
#endif
	}
	up_read(&lightswitch);
	return orig_count;
}

/*
 * POLL()
 */
static unsigned int user_poll(struct file *filp, poll_table *wait)
{
	if (!am_i_constable())
		return -EPERM;

	if (!atomic_read(&constable_present))
		return -EPIPE;
	poll_wait(filp, &userspace_chardev, wait);
	if (teleport.cycle != tpc_HALT) {
		return POLLIN | POLLRDNORM;
	} else if (atomic_read(&fetch_requests) || atomic_read(&update_requests) ||
		   atomic_read(&announce_ready) || atomic_read(&questions)) {
		return POLLIN | POLLRDNORM;
	} else if (atomic_read(&questions_waiting)) {
		return POLLOUT | POLLWRNORM;
	}
	// userspace_chardev wakes up only when adding teleport to the queue
	// for user to read
	return POLLOUT | POLLWRNORM;
}

/*
 * OPEN()
 */
static int user_open(struct inode *inode, struct file *file)
{
	int retval = -EPERM;
	struct teleport_insn_s *tele_mem_open = NULL;
	struct tele_item *local_tele_item;
	struct task_struct *parent;

	//MOD_INC_USE_COUNT; Not needed anymore JK

	down(&constable_openclose);
	if (atomic_read(&constable_present))
		goto out;
	medusa_server_health_mark_unhealthy(
		&constable_health, MEDUSA_HEALTH_DISCONNECTED);

	retval = -ENOMEM;
	if (med_cache_register(sizeof(struct tele_item)))
		goto out_free;
	if (med_cache_register(sizeof(struct teleport_insn_s) * 2))
		goto out_free;
	if (med_cache_register(sizeof(struct teleport_insn_s) * 5))
		goto out_free;
	if (med_cache_register(sizeof(struct teleport_insn_s) * 6))
		goto out_free;
	tele_mem_open = (struct teleport_insn_s *) med_cache_alloc_size(sizeof(struct teleport_insn_s)*3);
	if (!tele_mem_open)
		goto out_free;
	local_tele_item = (struct tele_item *) med_cache_alloc_size(sizeof(struct tele_item));
	if (!local_tele_item)
		goto out_free;

	constable = current;
	rcu_read_lock();
	parent = rcu_dereference(current->parent);
	task_lock(parent);
	if (strstr(current->parent->comm, "gdb"))
		gdb = current->parent;
	task_unlock(parent);
	rcu_read_unlock();

	teleport.cycle = tpc_HALT;
	// Reset semaphores
	sema_init(&user_read_lock, 1);
	sema_init(&queue_items, 0);
	sema_init(&queue_lock, 1);

	tele_mem_open[0].opcode = tp_PUTPtr;
	tele_mem_open[0].args.putPtr.what = (MCPptr_t)MEDUSA_COMM_GREETING;
	tele_mem_open[1].opcode = tp_PUTPtr;
	tele_mem_open[1].args.putPtr.what = (MCPptr_t)MEDUSA_COMM_VERSION;
	local_tele_item->size = sizeof(MCPptr_t)*2;
	tele_mem_open[2].opcode = tp_HALT;
	local_tele_item->tele = tele_mem_open;
	local_tele_item->post = med_cache_free;
	down(&queue_lock);
	list_add_tail(&local_tele_item->list, &tele_queue);
	up(&queue_lock);
	up(&queue_items);
	wake_up(&userspace_chardev);

	chardev_medusa.tgid = get_pid(task_tgid(current));

	retval = med_register_authserver_prepare(&chardev_medusa);
	if (retval < 0) {
		med_pr_warn("%s: med_register_authserver_prepare() failed with %d",
			    __func__, retval);
		teleport_clear();
		goto out;
	}

	retval = send_medusa_is_ready();
	if (retval < 0) {
		med_pr_warn("%s: send_medusa_is_ready() failed with %d",
			    __func__, retval);
		teleport_clear();
		goto out;
	}

	retval = med_authserver_handshake_begin(&chardev_medusa);
	if (retval < 0) {
		med_pr_warn("%s: authorization-server handshake already active\n",
			    __func__);
		teleport_clear();
		goto out;
	}

	/* this must be the last thing done */
	atomic_set(&constable_present, 1);
out:
	up(&constable_openclose);
	return retval; /* 0 is success */

out_free:
	if (tele_mem_open)
		med_cache_free(tele_mem_open);
	goto out;
}

/*
 * CLOSE()
 */
static int user_release(struct inode *inode, struct file *file)
{
	DECLARE_WAITQUEUE(waitqueue, current);

	// Operation close has to wait for read and write system calls to
	// finish.
	// Close has priority, so starvation can't occur. This is guaranteed by
	// the kernel if PREEMPT_RT is not set.
	down_write(&lightswitch);

	if (!atomic_read(&constable_present)) {
		up_write(&lightswitch);
		return 0;
	}

	/* this function is invoked also from context of process which requires decision
	 * after 5s of inactivity of our brave user space authorization server constable;
	 * so we comment next two lines ;)
	 */
	/*
	 * if (!am_i_constable())
	 * return 0;
	 */
	mutex_lock(&registration_lock);
	if (evtypes_registered) {
		struct medusa_evtype_s *p1, *p2;

		p1 = evtypes_registered;
		do {
			p2 = p1;
			p1 = (struct medusa_evtype_s *)p1->cinfo;
			// med_put_evtype(p2);
		} while (p1);
	}
	evtypes_registered = NULL;
	if (kclasses_registered) {
		struct medusa_kclass_s *p1, *p2;

		p1 = kclasses_registered;
		do {
			p2 = p1;
			p1 = (struct medusa_kclass_s *)p1->cinfo;
			med_put_kclass(p2);
		} while (p1);
	}
	kclasses_registered = NULL;
	mutex_unlock(&registration_lock);
	atomic_set(&fetch_requests, 0);
	atomic_set(&update_requests, 0);

	med_pr_info("Security daemon unregistered.\n");
#if defined(CONFIG_MEDUSA_HALT)
	med_pr_warn("No security daemon, system halted.\n");
	notifier_call_chain(&reboot_notifier_list, SYS_HALT, NULL);
	machine_halt();
#elif defined(CONFIG_MEDUSA_REBOOT)
	med_pr_warn("No security daemon, rebooting system.\n");
	ctrl_alt_del();
#endif
	add_wait_queue(&close_wait, &waitqueue);
	med_unregister_authserver(&chardev_medusa);
	down(&constable_openclose);

	// All threads waiting for an answer will get an error, order of these
	// functions is important!
	atomic_set(&constable_present, 0);
	medusa_server_health_mark_unhealthy(
		&constable_health, MEDUSA_HEALTH_DISCONNECTED);
	put_pid(chardev_medusa.tgid);
	chardev_medusa.tgid = NULL;
	constable = NULL;
	gdb = NULL;

	atomic_set(&questions, 0);
	atomic_set(&questions_waiting, 0);
	atomic_set(&announce_ready, 0);

	// Clear the teleport queue
	teleport_clear();

	medusa_pending_request_cancel_all(MED_ERR);

	up(&constable_openclose);
	// wake up waiting processes, this has to be outside of constable_openclose
	// lock because wake_up_all causes context switch (locking and unlocking
	// cpu may not be the same)
	if (am_i_constable()) {
		get_task_struct(current);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();
		put_task_struct(current);
	} else
		med_pr_crit("Authorization server is not responding.\n");
	remove_wait_queue(&close_wait, &waitqueue);
	//MOD_DEC_USE_COUNT; Not needed anymore? JK


	teleport.cycle = tpc_HALT;
	up_write(&lightswitch);
	return 0;
}

static struct class *medusa_class;
static struct device *medusa_device;

static int chardev_constable_init(void)
{
	med_pr_info("Registering L4 character device with major %d\n", MEDUSA_MAJOR);
	if (register_chrdev(MEDUSA_MAJOR, MODULENAME, &fops)) {
		med_pr_err("Cannot register character device with major %d\n", MEDUSA_MAJOR);
		return -1;
	}

	medusa_class = class_create("medusa");
	if (IS_ERR(medusa_class)) {
		med_pr_err("Failed to register device class '%s'\n", "medusa");
		return -1;
	}

	/* With a class, the easiest way to instantiate a device is to call device_create() */
	medusa_device = device_create(medusa_class, NULL, MKDEV(MEDUSA_MAJOR, 0), NULL, "medusa");
	if (IS_ERR(medusa_device)) {
		med_pr_err("Failed to create device '%s'\n", "medusa");
		return -1;
	}
	return 0;
}

static void chardev_constable_exit(void)
{
	device_destroy(medusa_class, MKDEV(MEDUSA_MAJOR, 0));
	class_unregister(medusa_class);
	class_destroy(medusa_class);

	unregister_chrdev(MEDUSA_MAJOR, MODULENAME);
}

module_init(chardev_constable_init);
module_exit(chardev_constable_exit);
MODULE_LICENSE("GPL");

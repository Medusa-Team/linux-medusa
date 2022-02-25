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
#include <linux/rwsem.h>

#include "l3/arch.h"
#include "l3/registry.h"
#include "l3/server.h"
#include "l3/med_cache.h"
#include "l4/comm.h"
#include "l4/teleport.h"

#define MEDUSA_MAJOR 111
#define MODULENAME "chardev/linux"

static int user_release(struct inode *inode, struct file *file);

static struct teleport_s teleport = {
	.cycle = tpc_HALT,
};

/* constable, our brave userspace daemon */
static atomic_t constable_present = ATOMIC_INIT(0);
static struct task_struct *constable;
static struct task_struct *gdb;
static DEFINE_SEMAPHORE(constable_openclose);


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
/* and the answer */
static enum medusa_answer_t user_answer = MED_ERR;
/* idr for storing answer ids */
static DEFINE_SPINLOCK(answer_ids_idr_lock);
static DEFINE_IDR(answer_ids_idr);

static DECLARE_WAIT_QUEUE_HEAD(close_wait);

static DECLARE_WAIT_QUEUE_HEAD(userspace_chardev);
static struct semaphore take_answer;
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
		struct medusa_kobject_s *o2);
static int l4_add_kclass(struct medusa_kclass_s *cl);
static int l4_add_evtype(struct medusa_evtype_s *at);
static void l4_close_wake(void);

static struct medusa_authserver_s chardev_medusa = {
	MODULENAME,
	0,	/* use-count */
	l4_close_wake,		/* close */
	l4_add_kclass,		/* add_kclass */
	NULL,			/* del_kclass */
	l4_add_evtype,		/* add_evtype */
	NULL,			/* del_evtype */
	l4_decide		/* decide */
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
		struct medusa_kobject_s *o1, struct medusa_kobject_s *o2)
{
	enum medusa_answer_t retval;
	struct teleport_insn_s *tele_mem_decide;
	struct tele_item *local_tele_item;
	int answer_id;

	if (!in_task()) {
		/* houston, we have a problem! */
		med_pr_err("%s called from interrupt context :(\n", __func__);
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
	if (!local_tele_item)
		return MED_ERR;
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

	spin_lock(&answer_ids_idr_lock);
	answer_id = idr_alloc_cyclic(&answer_ids_idr, current, 0, 0, GFP_ATOMIC);
	spin_unlock(&answer_ids_idr_lock);
	if (answer_id == -ENOMEM || answer_id == -ENOSPC) {
		med_cache_free(tele_mem_decide);
		med_cache_free(local_tele_item);
		up_read(&lightswitch);
		med_pr_err("%s: idr alloc error: %d\n", __func__, answer_id);
		return MED_ERR;
	}

#define decision_evtype (event->evtype_id)
	tele_mem_decide[0].opcode = tp_PUTPtr;
	tele_mem_decide[0].args.putPtr.what = (MCPptr_t)decision_evtype; // possibility to encryption JK march 2015
	local_tele_item->size += sizeof(MCPptr_t);
	tele_mem_decide[1].opcode = tp_PUTPtr;
	// idr uses only 32 lower bits from 64 bits of decision_request_id
	tele_mem_decide[1].args.putPtr.what = (MCPptr_t) answer_id;
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

	if (!atomic_read(&constable_present)) {
		med_cache_free(local_tele_item);
		med_cache_free(tele_mem_decide);
		spin_lock(&answer_ids_idr_lock);
		idr_remove(&answer_ids_idr, answer_id);
		spin_unlock(&answer_ids_idr_lock);
		up_read(&lightswitch);
		return MED_ERR;
	}
	med_pr_debug("new question %d pid %d\n", answer_id, current->pid);
	// prepare for next decision
#undef decision_evtype
	// insert teleport structure to the queue
	down(&queue_lock);
	list_add_tail(&local_tele_item->list, &tele_queue);
	up(&queue_lock);
	up(&queue_items);
	atomic_inc(&questions);

	// wait until answer is ready
	get_task_struct(current);
	up_read(&lightswitch);
	set_current_state(TASK_UNINTERRUPTIBLE);
	// Auth server shouldn't be notified earlier, so that it doesn't
	// answer the request before the task goes to sleep.
	wake_up(&userspace_chardev);
	schedule();
	put_task_struct(current);


	/*
	 * We might be called with the IPC ids->rwsem held (from IPC security
	 * hooks) and lightswitch should always nest inside the ids->rwsem one.
	 * Attention: authorization server must NOT use IPC subsystem at all to
	 * ========== avoid deadlock (trying to lock ids->rwsem inside the
	 *            lightswitch)!.
	 */
	down_read_nested(&lightswitch, SINGLE_DEPTH_NESTING);
	if (atomic_read(&constable_present)) {
		spin_lock(&answer_ids_idr_lock);
		idr_remove(&answer_ids_idr, answer_id);
		spin_unlock(&answer_ids_idr_lock);
		atomic_dec(&questions_waiting);
		retval = user_answer;
		med_pr_debug("question %d answered %i pid %d\n", answer_id, retval, current->pid);
	} else {
		retval = MED_ERR;
		med_pr_err("question %d not answered, authorization server disconnected\n",
			answer_id);
	}
	up(&take_answer);
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
	.llseek		= no_llseek, /* -ESPIPE */
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
			atomic_dec(&fetch_requests);
			break;
		case MEDUSA_COMM_UPDATE_ANSWER:
			atomic_dec(&update_requests);
			break;
		}
		break;
	case tp_PUTKCLASS:
	case tp_PUTEVTYPE:
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
	int answered_task_id;
	struct task_struct *answered_task;

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

	if (__copy_from_user(((char *)&recv_type), buf,
				sizeof(MCPptr_t))) {
		up_read(&lightswitch);
		med_pr_err("write: can't copy buffer\n");
		return -EFAULT;
	}
	buf += sizeof(MCPptr_t);
	count -= sizeof(MCPptr_t);

	// Type of the message is received
	down(&take_answer);
	if (recv_type == MEDUSA_COMM_AUTHANSWER) {
		if (__copy_from_user(recv_buf, buf, sizeof(int16_t) + sizeof(MCPptr_t))) {
			up(&take_answer);
			up_read(&lightswitch);
			med_pr_err("write: can't copy buffer\n");
			return -EFAULT;
		}
		buf += sizeof(int16_t) + sizeof(MCPptr_t);
		count -= sizeof(int16_t) + sizeof(MCPptr_t);

		user_answer = *(int16_t *)(recv_buf+sizeof(MCPptr_t));
		// space for decision_request_id is 64 bit, but idr uses only 32 bit
		answered_task_id = *(int *)(recv_buf);
		rcu_read_lock();
		//spin_lock(&answer_ids_idr_lock);
		answered_task = (struct task_struct *) idr_find(&answer_ids_idr, answered_task_id);
		//spin_unlock(&answer_ids_idr_lock);
		rcu_read_unlock();
		if (answered_task == NULL) {
			up(&take_answer);
			up_read(&lightswitch);
			med_pr_err("decision_answer: invalid decision_request_id: %llx\n", *(uint64_t *)(recv_buf));
			return -100;
		}
		med_pr_debug("answer received for %llx pid %d\n", *(uint64_t *)(recv_buf), answered_task->pid);
		// wake up correct process
		while (!wake_up_process(answered_task))
			// wait for `answered_task` to sleep if it's not sleeping yet
			schedule();

	} else if (recv_type == MEDUSA_COMM_FETCH_REQUEST ||
			recv_type == MEDUSA_COMM_UPDATE_REQUEST) {
		up(&take_answer);
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
		if (!tele_mem_write)
			return -ENOMEM;
		local_tele_item = (struct tele_item *) med_cache_alloc_size(sizeof(struct tele_item));
		if (!local_tele_item) {
			med_cache_free(tele_mem_write);
			return -ENOMEM;
		}
		local_tele_item->size = 0;
		tele_mem_write[0].opcode = tp_PUTPtr;
		tele_mem_write[0].args.putPtr.what = 0;
		local_tele_item->size += sizeof(MCPptr_t);
		tele_mem_write[1].opcode = tp_PUT32;
		if (recv_type == MEDUSA_COMM_FETCH_REQUEST) { /* fetch */
			atomic_inc(&fetch_requests);
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
			atomic_inc(&update_requests);
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
		wake_up(&userspace_chardev);
	} else {
		up(&take_answer);
		med_pr_err("Protocol error at write(): unknown command %llx!\n",
			(MCPptr_t)recv_type);
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
	struct teleport_insn_s *tele_mem_open;
	struct tele_item *local_tele_item;
	struct task_struct *parent;

	//MOD_INC_USE_COUNT; Not needed anymore JK

	down(&constable_openclose);
	if (atomic_read(&constable_present))
		goto good_out;

	if (med_cache_register(sizeof(struct tele_item))) {
		retval = -ENOMEM;
		goto out;
	}
	if (med_cache_register(sizeof(struct teleport_insn_s)*2)) {
		retval = -ENOMEM;
		goto out;
	}
	if (med_cache_register(sizeof(struct teleport_insn_s)*5)) {
		retval = -ENOMEM;
		goto out;
	}
	if (med_cache_register(sizeof(struct teleport_insn_s)*6)) {
		retval = -ENOMEM;
		goto out;
	}
	tele_mem_open = (struct teleport_insn_s *) med_cache_alloc_size(sizeof(struct teleport_insn_s)*3);
	if (!tele_mem_open) {
		retval = -ENOMEM;
		goto out;
	}
	local_tele_item = (struct tele_item *) med_cache_alloc_size(sizeof(struct tele_item));
	if (!local_tele_item) {
		retval = -ENOMEM;
		goto out;
	}

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
	sema_init(&take_answer, 1);
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

	/* this must be the last thing done */
	atomic_set(&constable_present, 1);
	up(&constable_openclose);

	MED_REGISTER_AUTHSERVER(chardev_medusa);
	return 0; /* success */
out:
	if (tele_mem_open)
		med_cache_free(tele_mem_open);
good_out:
	up(&constable_openclose);
	return retval;
}

/*
 * CLOSE()
 */
static int user_release(struct inode *inode, struct file *file)
{
	struct list_head *pos, *next;
	int answer_id;
	struct task_struct *task;
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
	MED_UNREGISTER_AUTHSERVER(chardev_medusa);
	down(&constable_openclose);

	// All threads waiting for an answer will get an error, order of these
	// functions is important!
	user_answer = MED_ERR;
	atomic_set(&constable_present, 0);
	constable = NULL;
	gdb = NULL;

	atomic_set(&questions, 0);
	atomic_set(&questions_waiting, 0);
	atomic_set(&announce_ready, 0);

	// Clear the teleport queue
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

	// locking not needed because lightswitch is locked by one thread running close()
	idr_for_each_entry(&answer_ids_idr, task, answer_id) 
		wake_up_process(task);
	idr_destroy(&answer_ids_idr);

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

	medusa_class = class_create(THIS_MODULE, "medusa");
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

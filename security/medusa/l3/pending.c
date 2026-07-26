// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>

#include "l3/pending.h"

#define MEDUSA_PENDING_HASH_BITS	10

static DEFINE_HASHTABLE(pending_requests, MEDUSA_PENDING_HASH_BITS);
static DEFINE_SPINLOCK(pending_requests_lock);
static atomic64_t next_request_id = ATOMIC64_INIT(0);
static unsigned int pending_request_count;

static struct medusa_pending_request *find_pending_request(u64 id)
{
	struct medusa_pending_request *request;

	hash_for_each_possible(pending_requests, request, table_node, id) {
		if (request->id == id)
			return request;
	}
	return NULL;
}

int medusa_pending_request_register(struct medusa_pending_request *request,
				    u64 policy_generation)
{
	u64 id;
	int error = 0;

	init_completion(&request->done);
	init_waitqueue_head(&request->state_changed);
	INIT_HLIST_NODE(&request->table_node);
	request->answer = MED_ERR;
	request->policy_generation = policy_generation;
	request->lease_sequence = 0;
	request->registered = false;

	spin_lock(&pending_requests_lock);
	if (pending_request_count >= MEDUSA_PENDING_REQUEST_LIMIT) {
		error = -ENOSPC;
		goto out;
	}

	do {
		id = atomic64_inc_return(&next_request_id);
	} while (!id || find_pending_request(id));

	request->id = id;
	request->registered = true;
	hash_add(pending_requests, &request->table_node, request->id);
	pending_request_count++;
out:
	spin_unlock(&pending_requests_lock);
	return error;
}

void medusa_pending_request_unregister(struct medusa_pending_request *request)
{
	spin_lock(&pending_requests_lock);
	if (request->registered) {
		hlist_del_init(&request->table_node);
		request->registered = false;
		pending_request_count--;
	}
	spin_unlock(&pending_requests_lock);
}

int medusa_pending_request_complete(u64 id, u64 policy_generation,
				    enum medusa_answer_t answer)
{
	struct medusa_pending_request *request;
	int error = 0;

	spin_lock(&pending_requests_lock);
	request = find_pending_request(id);
	if (!request) {
		error = -ENOENT;
		goto out;
	}
	if (request->policy_generation != policy_generation) {
		error = -ESTALE;
		goto out;
	}

	hlist_del_init(&request->table_node);
	request->registered = false;
	pending_request_count--;
	request->answer = answer;
	complete(&request->done);
	wake_up_all(&request->state_changed);
out:
	spin_unlock(&pending_requests_lock);
	return error;
}

int medusa_pending_request_renew(u64 id, u64 policy_generation)
{
	struct medusa_pending_request *request;
	int error = 0;

	spin_lock(&pending_requests_lock);
	request = find_pending_request(id);
	if (!request) {
		error = -ENOENT;
		goto out;
	}
	if (request->policy_generation != policy_generation) {
		error = -ESTALE;
		goto out;
	}

	request->lease_sequence++;
	wake_up_all(&request->state_changed);
out:
	spin_unlock(&pending_requests_lock);
	return error;
}

enum medusa_answer_t
medusa_pending_request_wait(struct medusa_pending_request *request)
{
	wait_for_completion(&request->done);
	return request->answer;
}

int medusa_pending_request_wait_timeout(
	struct medusa_pending_request *request, unsigned long timeout,
	enum medusa_answer_t *answer)
{
	u64 lease_sequence;

	for (;;) {
		spin_lock(&pending_requests_lock);
		if (!request->registered) {
			*answer = request->answer;
			spin_unlock(&pending_requests_lock);
			return 0;
		}
		lease_sequence = request->lease_sequence;
		spin_unlock(&pending_requests_lock);

		if (wait_event_timeout(
			    request->state_changed,
			    !READ_ONCE(request->registered) ||
			    READ_ONCE(request->lease_sequence) != lease_sequence,
			    timeout))
			continue;

		spin_lock(&pending_requests_lock);
		if (request->registered &&
		    request->lease_sequence == lease_sequence) {
			hlist_del_init(&request->table_node);
			request->registered = false;
			pending_request_count--;
			spin_unlock(&pending_requests_lock);
			*answer = MED_ERR;
			return -ETIMEDOUT;
		}
		spin_unlock(&pending_requests_lock);
	}
}

void medusa_pending_request_cancel_all(enum medusa_answer_t answer)
{
	struct medusa_pending_request *request;
	struct hlist_node *temporary;
	unsigned int bucket;

	spin_lock(&pending_requests_lock);
	hash_for_each_safe(pending_requests, bucket, temporary, request,
			   table_node) {
		hlist_del_init(&request->table_node);
		request->registered = false;
		pending_request_count--;
		request->answer = answer;
		complete(&request->done);
		wake_up_all(&request->state_changed);
	}
	spin_unlock(&pending_requests_lock);
}

unsigned int medusa_pending_request_count(void)
{
	unsigned int count;

	spin_lock(&pending_requests_lock);
	count = pending_request_count;
	spin_unlock(&pending_requests_lock);
	return count;
}

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _MEDUSA_PENDING_H
#define _MEDUSA_PENDING_H

#include <linux/completion.h>
#include <linux/list.h>
#include <linux/types.h>

#include "l3/constants.h"

#define MEDUSA_PENDING_REQUEST_LIMIT	1024U

struct medusa_pending_request {
	struct completion done;
	wait_queue_head_t state_changed;
	struct hlist_node table_node;
	u64 id;
	u64 policy_generation;
	u64 lease_sequence;
	enum medusa_answer_t answer;
	bool registered;
};

int medusa_pending_request_register(struct medusa_pending_request *request,
				    u64 policy_generation);
void medusa_pending_request_unregister(struct medusa_pending_request *request);
int medusa_pending_request_complete(u64 id, u64 policy_generation,
				    enum medusa_answer_t answer);
int medusa_pending_request_renew(u64 id, u64 policy_generation);
enum medusa_answer_t
medusa_pending_request_wait(struct medusa_pending_request *request);
int medusa_pending_request_wait_timeout(
	struct medusa_pending_request *request, unsigned long timeout,
	enum medusa_answer_t *answer);
void medusa_pending_request_cancel_all(enum medusa_answer_t answer);
unsigned int medusa_pending_request_count(void);

#endif /* _MEDUSA_PENDING_H */

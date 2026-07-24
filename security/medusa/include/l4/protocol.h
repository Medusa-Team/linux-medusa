/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _MEDUSA_PROTOCOL_H
#define _MEDUSA_PROTOCOL_H

#include <linux/errno.h>
#include <linux/types.h>

#include "l3/constants.h"
#include "l4/comm.h"

#define MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE \
	(sizeof(MCPptr_t) + sizeof(s16))

static inline int medusa_comm_validate_authanswer(size_t payload_size,
						   s16 answer,
						   bool request_pending)
{
	if (payload_size != MEDUSA_COMM_AUTHANSWER_PAYLOAD_SIZE)
		return -EMSGSIZE;
	if (answer != MED_ALLOW && answer != MED_DENY && answer != MED_ERR)
		return -EINVAL;
	if (!request_pending)
		return -ENOENT;
	return 0;
}

#endif /* _MEDUSA_PROTOCOL_H */

/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _MEDUSA_PROTOCOL_H
#define _MEDUSA_PROTOCOL_H

#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/medusa.h>

#include "l3/constants.h"

static inline bool
medusa_v4_message_allowed(enum medusa_protocol_state state, u16 type)
{
	switch (state) {
	case MEDUSA_STATE_HANDSHAKE:
		return type == MEDUSA_MSG_HELLO;
	case MEDUSA_STATE_DEFINITIONS:
		return type == MEDUSA_MSG_POLICY_BEGIN;
	case MEDUSA_STATE_POLICY_INSTALL:
		return type == MEDUSA_MSG_POLICY_EVENT ||
		       type == MEDUSA_MSG_POLICY_COMMIT;
	case MEDUSA_STATE_READY:
		return type == MEDUSA_MSG_DECISION_REPLY ||
		       type == MEDUSA_MSG_DECISION_PROGRESS ||
		       type == MEDUSA_MSG_OBJECT_FETCH ||
		       type == MEDUSA_MSG_OBJECT_UPDATE;
	default:
		return false;
	}
}

static inline int medusa_v4_validate_answer(s16 answer)
{
	if (answer != MED_ERR && answer != MED_DENY && answer != MED_ALLOW)
		return -EINVAL;
	return 0;
}

static inline int medusa_v4_validate_fallback_policy(u8 policy)
{
	if (policy > MEDUSA_FALLBACK_ONLINE_REQUIRED)
		return -EINVAL;
	return 0;
}

static inline int medusa_v4_negotiate_features(u64 required, u64 optional,
					       u64 *enabled)
{
	if (required & ~MEDUSA_SUPPORTED_FEATURES)
		return -EOPNOTSUPP;
	*enabled = required | (optional & MEDUSA_SUPPORTED_FEATURES);
	return 0;
}

#endif /* _MEDUSA_PROTOCOL_H */

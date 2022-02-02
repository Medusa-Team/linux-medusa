/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_L2_H
#define _MEDUSA_L2_H

/*
 * lsm_retval - translate a Medusa's answer code to a LSM return value
 * @ans: medusa's answer code
 * @err: optional error code to return
 *
 * Return a valid return value for LSM framework based on @ans and @err:
 * 1) @err value, if it is desired to deliver an arbitrary error code
 * 2) -EACCES if @ans is MED_DENY (Medusa denied the operation)
 * 3) 0 if Medusa permitted the operation
 */
static inline int lsm_retval(enum medusa_answer_t ans, int err)
{
	if (unlikely(err))
		return err;
	if (ans == MED_DENY)
		return -EACCES;
	return 0;
}

#endif

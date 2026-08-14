/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_L1_PATH_GUARD_H
#define _MEDUSA_L1_PATH_GUARD_H

#include "l3/registry.h"
#include "l1/inode.h"

/* Release all path-integrity entries owned by an inode security context. */
bool path_guard_has_entries(struct medusa_l1_inode_s *context);
int path_guard_free(struct medusa_l1_inode_s *med);

#endif

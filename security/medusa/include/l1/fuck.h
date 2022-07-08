/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_L1_FUCK_H
#define _MEDUSA_L1_FUCK_H

#include "l3/registry.h"
#include "l1/inode.h"

/* prototypes of L2 fuck related handlers called from L1 hooks */

int validate_fuck(const struct path *fuck_path);
int fuck_free(struct medusa_l1_inode_s *med);

#endif


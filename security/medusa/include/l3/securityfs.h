/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _MEDUSA_SECURITYFS_H
#define _MEDUSA_SECURITYFS_H

#include <linux/init.h>

struct file;

int __init medusa_securityfs_init(void);
bool medusa_securityfs_file(const struct file *file);

#endif /* _MEDUSA_SECURITYFS_H */

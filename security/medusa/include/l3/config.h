/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_CONFIG_H
#define _MEDUSA_CONFIG_H

#include <linux/spinlock.h>

#define IS_NOT_MULTIPLY_OF_8(val) (val & 7 != 0)

#ifdef CONFIG_SECURITY_MEDUSA_VS
#define CONFIG_MEDUSA_VS CONFIG_SECURITY_MEDUSA_VS
#else
#define CONFIG_MEDUSA_VS 96
#endif

/*
 * Medusa Communication Protocol transfers size of attributes in Bytes.
 * To prevent a mistake and errornous interpretation of bits out of
 * bitarray, the array size CONFIG_MEDUSA_VS must be a multiple of 8.
 */
#if IS_NOT_MULTIPLY_OF_8(CONFIG_MEDUSA_VS)
#error "CONFIG_MEDUSA_VS is not a multiple of 8"
#endif

#ifdef CONFIG_SECURITY_MEDUSA_ACT
#define CONFIG_MEDUSA_ACT CONFIG_SECURITY_MEDUSA_ACT
#else
#define CONFIG_MEDUSA_ACT 128
#endif

/*
 * Medusa Communication Protocol transfers size of attributes in Bytes.
 * To prevent a mistake and errornous interpretation of bits out of
 * bitarray, the array size CONFIG_MEDUSA_ACT must be a multiple of 8.
 */
#if IS_NOT_MULTIPLY_OF_8(CONFIG_MEDUSA_ACT)
#error "CONFIG_MEDUSA_ACT is not a multiple of 8"
#endif

/*
 * Id of an event type is stored in event's `bitnr` struct member and
 * that id is 14 bits long, but one value is used for special purpose,
 * so there are 2^14-1 usable values (see include/l3/kobject.h). If
 * CONFIG_MEDUSA_ACT exceedes this value, a compilation error is raised.
 */
#if (CONFIG_MEDUSA_ACT >= 0x3fff)
#error "CONFIG_MEDUSA_ACT should be < (2^14-1)"
#endif

#define CONFIG_MEDUSA_FILE_CAPABILITIES
#define CONFIG_MEDUSA_FORCE
#define CONFIG_MEDUSA_SYSCALL
#define DEBUG
#define ERRORS_CAUSE_SEGFAULT
#define GDB_HACK
#define PARANOIA_CHECKS

#endif

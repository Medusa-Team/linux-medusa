/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_CONSTANTS_H
#define _MEDUSA_CONSTANTS_H

#include <uapi/linux/medusa.h>

/* these constants may be used by both internal kernel data structures,
 * and a communication protocol. if you alter them, you'll break the
 * comm protocol, and build of some l4 servers might fail.
 *
 * moreover, if you change the medusa_answer_t, the world will die in pain.
 */

/* elementary data types for attributes */
#define MED_END		MEDUSA_ATTR_END
#define MED_UNSIGNED	MEDUSA_ATTR_UNSIGNED
#define MED_SIGNED	MEDUSA_ATTR_SIGNED
#define MED_STRING	MEDUSA_ATTR_STRING
#define	MED_BITMAP	MEDUSA_ATTR_BITMAP
#define	MED_BYTES	MEDUSA_ATTR_BYTES

/* Internal attribute flags; translated to UAPI flags by protocol v4. */
#define MED_KEY		0x40U
#define MED_RO		0x80U
#define MED_LE		0x30U
#define MED_BE		0x20U

/* string lengths in various structures */
#define MEDUSA_ATTRNAME_MAX	27
#define MEDUSA_KCLASSNAME_MAX	30
#define MEDUSA_EVNAME_MAX	30
#define MEDUSA_ACCNAME_MAX	MEDUSA_EVNAME_MAX
#define MEDUSA_SERVERNAME_MAX	128

#define not_supported ("do not use - behavior not supported by LSM")

enum medusa_answer_t {
	MED_ERR =		-1,	/* error */
	MED_FORCE_ALLOW __attribute__ ((deprecated(not_supported))),	/* permit the operation */
	MED_DENY =		 1,	/* forbid the operation */
	MED_FAKE_ALLOW __attribute__ ((deprecated(not_supported))),	/* forbid the operation, but return success */
	MED_ALLOW =		 3	/* permit the operation, but proceed with standard system permission check if any */
};

#endif

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _MEDUSA_AUDIT_SCHEMA_H
#define _MEDUSA_AUDIT_SCHEMA_H

/*
 * Increment only for an incompatible change to the machine-readable Medusa
 * fields documented in security/medusa/AUDIT.rst. Record-specific fields may
 * be appended without changing the version.
 */
#define MEDUSA_AUDIT_SCHEMA_VERSION	1U

#define MEDUSA_AUDIT_RECORD_DECISION		"decision"
#define MEDUSA_AUDIT_RECORD_PROTOCOL_ERROR	"protocol_error"

#endif /* _MEDUSA_AUDIT_SCHEMA_H */

/* SPDX-License-Identifier: GPL-2.0 */

/* (C) 2002 Milan Pikula
 *
 * This header file defines the routines and data structures
 * for L2 and L4 code to interact with L3. This means access
 * to both registry functions, and decision process.
 *
 * The name or contents of this file should probably change.
 */

#ifndef _MEDUSA_REGISTRY_H
#define _MEDUSA_REGISTRY_H

#include "l3/arch.h"
#include "l3/health.h"
#include "l3/kobject.h"
#include "l3/server.h"

struct seq_file;

enum medusa_authserver_state {
	MEDUSA_AUTHSERVER_DISCONNECTED,
	MEDUSA_AUTHSERVER_HANDSHAKE,
	MEDUSA_AUTHSERVER_DEFINITIONS,
	MEDUSA_AUTHSERVER_POLICY_INSTALL,
	MEDUSA_AUTHSERVER_READY,
	MEDUSA_AUTHSERVER_DEGRADED,
};

#define MEDUSA_AUTHSERVER_HANDSHAKING MEDUSA_AUTHSERVER_HANDSHAKE

struct medusa_registry_status {
	u64 policy_generation;
	u64 active_policy_generation;
	u64 last_ready_policy_generation;
	char server_name[MEDUSA_SERVERNAME_MAX];
	enum medusa_health_reason health_reason;
	enum medusa_authserver_state server_state;
	bool connected;
	bool health_known;
	bool healthy;
};

/* interface to L2 */
extern int med_register_kclass(struct medusa_kclass_s *med_kclass);
extern int med_unlink_kclass(struct medusa_kclass_s *med_kclass);
extern int med_unregister_kclass(struct medusa_kclass_s *med_kclass);
#define MED_REGISTER_KCLASS(structname) \
		med_register_kclass(&MED_KCLASSOF(structname))
#define MED_UNLINK_KCLASS(structname) \
		med_unlink_kclass(&MED_KCLASSOF(structname))
#define MED_UNREGISTER_KCLASS(structname) \
		med_unregister_kclass(&MED_KCLASSOF(structname))

extern int med_register_evtype(struct medusa_evtype_s *med_evtype, int flags);
extern void med_unregister_evtype(struct medusa_evtype_s *med_evtype);
#define MED_REGISTER_EVTYPE(structname, flags) \
		med_register_evtype(&MED_EVTYPEOF(structname), flags)
#define MED_UNREGISTER_EVTYPE(structname) \
		med_unregister_evtype(&MED_EVTYPEOF(structname))

#define MED_REGISTER_ACCTYPE(structname, flags) \
		MED_REGISTER_EVTYPE(structname, flags)
#define MED_UNREGISTER_ACCTYPE(structname) \
		MED_UNREGISTER_EVTYPE(structname)
/* here, the 'flags' field is one of
 *	MEDUSA_ACCTYPE_NOTTRIGGERED (monitoring of this event can't be turned off),
 *	MEDUSA_ACCTYPE_TRIGGEREDATOBJECT (the event is triggered by changing the object)
 *	MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT (the ... subject)
 */

#define MED_DECIDE(structname, arg1, arg2, arg3) \
		med_decide(&MED_EVTYPEOF(structname), arg1, arg2, arg3)
#define MED_DECIDE_RESULT(structname, arg1, arg2, arg3) \
		med_decide_result(&MED_EVTYPEOF(structname), arg1, arg2, arg3)

/* interface to L2 and L4 */
extern void med_get_kclass(struct medusa_kclass_s *med_kclass);
extern void med_put_kclass(struct medusa_kclass_s *med_kclass);
extern struct medusa_kclass_s *med_get_kclass_by_pointer(struct medusa_kclass_s *med_kclass);
extern struct medusa_authserver_s *med_get_authserver(void);
extern void med_put_authserver(struct medusa_authserver_s *med_authserver);
extern inline bool med_is_authserver_present(void);
void medusa_registry_status_snapshot(struct medusa_registry_status *status);
int medusa_registry_events_seq_show(struct seq_file *m);
int medusa_registry_classes_seq_show(struct seq_file *m);
void medusa_event_set_enforced(
	struct medusa_evtype_s *evtype,
	enum medusa_delegation_context delegation_context);
const char *medusa_delegation_context_name(
	enum medusa_delegation_context delegation_context);

/* interface to L4 */
extern int med_register_authserver_prepare(struct medusa_authserver_s *med_authserver);
int med_authserver_handshake_begin(struct medusa_authserver_s *med_authserver);
int med_authserver_set_state(struct medusa_authserver_s *med_authserver,
			     enum medusa_authserver_state state);
int med_authserver_stage_fallback_policy(
	struct medusa_authserver_s *med_authserver,
	struct medusa_evtype_s *event_id,
	enum medusa_fallback_policy policy);
int med_authserver_policy_replace_begin(
	struct medusa_authserver_s *med_authserver);
int med_authserver_policy_replace_commit(
	struct medusa_authserver_s *med_authserver);
int med_authserver_policy_replace_abort(
	struct medusa_authserver_s *med_authserver);
extern int med_register_authserver(struct medusa_authserver_s *med_authserver);
extern void med_unregister_authserver(struct medusa_authserver_s *med_authserver);
const char *medusa_authserver_state_name(enum medusa_authserver_state state);

#endif

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
#include "l3/kobject.h"
#include "l3/server.h"

extern int authserver_magic; /* to be checked against magic in objects */

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

extern enum medusa_answer_t med_decide(struct medusa_evtype_s *, void *, void *, void *);
#define MED_DECIDE(structname, arg1, arg2, arg3) \
		med_decide(&MED_EVTYPEOF(structname), arg1, arg2, arg3)

/* interface to L2 and L4 */
extern void med_get_kclass(struct medusa_kclass_s *med_kclass);
extern void med_put_kclass(struct medusa_kclass_s *med_kclass);
extern struct medusa_kclass_s *med_get_kclass_by_pointer(struct medusa_kclass_s *med_kclass);
extern struct medusa_authserver_s *med_get_authserver(void);
extern void med_put_authserver(struct medusa_authserver_s *med_authserver);
extern inline bool med_is_authserver_present(void);

/* interface to L4 */
extern int med_register_authserver(struct medusa_authserver_s *med_authserver);
extern void med_unregister_authserver(struct medusa_authserver_s *med_authserver);
#define MED_REGISTER_AUTHSERVER(structname) \
		med_register_authserver(&structname)
#define MED_UNREGISTER_AUTHSERVER(structname) \
		med_unregister_authserver(&structname)

#endif

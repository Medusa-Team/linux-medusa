/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_KOBJECT_H
#define _MEDUSA_KOBJECT_H

/*
 * Used by l2, l3, l4
 *
 * This file defines
 *	ATTRIBUTE TYPE (defined in l2, used by l4)	medusa_attribute_s
 *
 *	KCLASS (defined in l2, used by l3, l4)		medusa_kclass_s
 *	KOBJECT (defined in l2, used by l3, l4)		medusa_kobject_s
 *
 *	EVENT TYPE (defined in l2, used by l4)		medusa_evtype_s
 *		(and ACCESS TYPE)
 *	EVENT (defined in l2, used by l3, l4)		medusa_event_s
 *		(and ACCESS)
 */

/*
 * While you are not looking, this source is in Pascal.
 */

#include <linux/types.h>
#include "l3/arch.h"
#include "l3/constants.h"
#include "l3/med_model.h"

struct medusa_attribute_s;
struct medusa_kclass_s;
struct medusa_kobject_s;
struct medusa_evtype_s;

/**/
/**/

/* describes one attribute in kclass (defined in l2 code, used by l4) */
struct medusa_attribute_s {
	char name[MEDUSA_ATTRNAME_MAX];	/* string: attribute name */
	unsigned int type;		/* data type (MED_xxx) */
	unsigned long offset;		/* offset of attribute in kobject */
	unsigned long length;		/* bytes consumed by data */
};

#define MED_ATTRSOF(structname) (structname##_attrs)

/* macros for l2 to simplify attribute definitions */
#define MED_ATTRS(structname) struct medusa_attribute_s (MED_ATTRSOF(structname))[] =

#define MED_ATTR_ORIG(structname, structmember, structmembersize, attrname, medtype) { \
		(attrname), \
		(medtype), \
		(MCPptr_t)(&(((struct structname *)0)->structmember)), \
		structmembersize, \
	}
#define MED_ATTR_END {"", MED_END, 0, 0}

#define _MED_ATTR_5(sn, sm, sz, an, ty) MED_ATTR_ORIG(sn, sm, sz, an, ty)
#define _MED_ATTR_RO_5(sn, sm, sz, an, ty) MED_ATTR_ORIG(sn, sm, sz, an, (ty) | MED_RO)
#define _MED_ATTR_KEY_5(sn, sm, sz, an, ty) MED_ATTR_ORIG(sn, sm, sz, an, (ty) | MED_KEY)
#define _MED_ATTR_KEY_RO_5(sn, sm, sz, an, ty) MED_ATTR_ORIG(sn, sm, sz, an, (ty) | MED_KEY | MED_RO)
#define _MED_ATTR_4(sn, sm, an, ty) MED_ATTR_ORIG(sn, sm, sizeof(((struct sn *)0)->sm), an, ty)
#define _MED_ATTR_RO_4(sn, sm, an, ty) MED_ATTR_ORIG(sn, sm, sizeof(((struct sn *)0)->sm), an, (ty) | MED_RO)
#define _MED_ATTR_KEY_4(sn, sm, an, ty) MED_ATTR_ORIG(sn, sm, sizeof(((struct sn *)0)->sm), an, (ty) | MED_KEY)
#define _MED_ATTR_KEY_RO_4(sn, sm, an, ty) MED_ATTR_ORIG(sn, sm, sizeof(((struct sn *)0)->sm), an, (ty) | MED_KEY | MED_RO)
#define _MED_ATTR(_1, _2, _3, _4, _5, __MED_ATTR, ...) __MED_ATTR

/*
 * Following four MED_ATTR* macros can take 4 or 5 arguments in this order:
 *	structname, structmember, (structmembersize,) attrname, medtype
 * The `structmembersize` allows to specify the real size of `structmember`
 * if its size differs from memory size of implementing type. For example,
 * kernel bitmaps are formed on x64 architecture using an array of uin64
 * elements, but the real number of bits used is up to the programmer. This is
 * the case of Medusa's virtual spaces or subject's (object's) bitarray of
 * events, that may be triggered.
 *
 * If `structmembersize` argument is not given, size of `structmember`'s memory
 * representation is used. This is the most common case, so for simplicity,
 * readability and backward compatibility of l2 code, versions of macros with
 * four arguments also remain.
 */
#define MED_ATTR(...) _MED_ATTR(__VA_ARGS__, _MED_ATTR_5, _MED_ATTR_4)(__VA_ARGS__)
#define MED_ATTR_RO(...) _MED_ATTR(__VA_ARGS__, _MED_ATTR_RO_5, _MED_ATTR_RO_4)(__VA_ARGS__)
#define MED_ATTR_KEY(...) _MED_ATTR(__VA_ARGS__, _MED_ATTR_KEY_5, _MED_ATTR_KEY_4)(__VA_ARGS__)
#define MED_ATTR_KEY_RO(...) _MED_ATTR(__VA_ARGS__, _MED_ATTR_KEY_RO_5, _MED_ATTR_KEY_RO_4)(__VA_ARGS__)

#define MED_ATTR_SUBJECT(sn) /* internal macro copying medusa/l3/model.h */ \
	MED_ATTR(sn, med_subject.vsr, CONFIG_MEDUSA_VS >> 3, "vsr", MED_BITMAP),	/* type vs_t */ \
	MED_ATTR(sn, med_subject.vsw, CONFIG_MEDUSA_VS >> 3, "vsw", MED_BITMAP),	/* type vs_t */ \
	MED_ATTR(sn, med_subject.vss, CONFIG_MEDUSA_VS >> 3, "vss", MED_BITMAP),	/* type vs_t */ \
	MED_ATTR(sn, med_subject.act, CONFIG_MEDUSA_ACT >> 3, "med_sact", MED_BITMAP),	/* type act_t */ \
	MED_ATTR(sn, med_subject.cinfo, sizeof(struct s_cinfo_t), "s_cinfo", MED_BITMAP)/* type s_cinfo_t */
#define MED_ATTR_OBJECT(sn) /* internal macro copying medusa/l3/model.h */ \
	MED_ATTR(sn, med_object.vs, CONFIG_MEDUSA_VS >> 3, "vs", MED_BITMAP),		/* type vs_t */ \
	MED_ATTR(sn, med_object.act, CONFIG_MEDUSA_ACT >> 3, "med_oact", MED_BITMAP),	/* type act_t */ \
	MED_ATTR(sn, med_object.cinfo, sizeof(struct s_cinfo_t), "o_cinfo", MED_BITMAP)	/* type o_cinfo_t */

/**/
/**/

/* description of kclass (defined in l2 code, used by l3, l4) */
#define MED_KCLASSOF(structname) (structname##_kclass)
#define MED_DECLARE_KCLASSOF(structname) struct medusa_kclass_s (structname##_kclass)
struct medusa_kclass_s {
	/* l3-defined data, filled by register_kobject */
	struct medusa_kclass_s *next;	/* through all kclasses */
	int use_count;
	void *cinfo; /* l4 hint: must be able to hold pointer for linked list of registered kclass */
#ifdef CONFIG_MEDUSA_PROFILING
	unsigned long long l2_to_l4;
	unsigned long long l4_to_l2;
#endif

	/* l2-defined data */
	unsigned int kobject_size;		/* sizeof(kobject) */
	struct medusa_attribute_s *attr;	/* attributes */
	char name[MEDUSA_KCLASSNAME_MAX];	/* string: kclass name */
	void *reg;
	void *unreg;
	struct medusa_kobject_s *(*fetch)(struct medusa_kobject_s *key_obj); /* fetch the kobj. by key */
	enum medusa_answer_t (*update)(struct medusa_kobject_s *kobj); /* update the kobj. */
	void (*unmonitor)(struct medusa_kobject_s *kobj); /* disable all monitoring on kobj. optional; cannot sleep. */
};

#ifdef CONFIG_MEDUSA_PROFILING
#define MEDUSA_DEFAULT_KCLASS_HEADER \
	NULL, 0,	/* register_kclass */	\
	0,		/* cinfo */		\
	0, 0		/* stats */
#else
#define MEDUSA_DEFAULT_KCLASS_HEADER \
	NULL, 0,	/* register_kclass */	\
	0		/* cinfo */
#endif

/* macros for l2 to simplify kclass definition */
#define MED_KCLASS(structname) struct medusa_kclass_s (MED_KCLASSOF(structname)) =
#define MEDUSA_KCLASS_HEADER(structname) \
	MEDUSA_DEFAULT_KCLASS_HEADER, \
	sizeof(struct structname), \
	MED_ATTRSOF(structname)

/**/
/**/

/* used by l3 and l4 to easily access the header of l2 structures */
struct medusa_kobject_s {
	unsigned char data[0];
};

/*
 * In the `medusa_evtype_s` struct (see below) the `bitnr` member is defined
 * as a 16-bit unsigned short integer. It holds the position of a bit which
 * triggers monitoring of a given evtype.
 * The two MSBs of `bitnr` are used to determine:
 *   1) If the first MSB is set (0x8000), the event is triggered at object;
 *      if it is not set, the event is triggered at subject.
 *   2) The second MSB (0x4000) is used to determine, which struct
 *      (object or subject) is used to get the monitoring bitfield `act`:
 *      if set to 1, `med_object.act` is used, otherwise `med_subject.act`.
 *
 * There can be max CONFIG_MEDUSA_ACT registered evtypes triggered at object,
 * and the same count of evtypes triggered at subject. Checks are done in
 * `med_register_evtype()` at l3/registry.c file. As `bitnr` has 16 bits,
 * from which two MSBs are reserved, 14 bits are sufficient to identify
 * 2^14-1 different evtypes. Special value 0x3fff is reserved for evtypes, where
 * the triggering cannot be turned off, i.e. all evtypes used to initialize VS
 * model of an object (subject) in the kernel.
 *
 * If you change the number of `bitnr` bits, see also include/l3/config.h for
 * CONFIG_MEDUSA_ACT constraints.
 */
#define MED_EVTYPEOF(structname) (structname##_evtype)
struct medusa_evtype_s {
	/* l3-defined data */
	struct medusa_evtype_s *next;
	unsigned short bitnr;	/* which bit at subject or object triggers
				 * monitoring of this evtype. The value is
				 * OR'd with these flags:
				 */
	/* if you change/swap them, check the usage anywhere (l3/registry.c) */
#define MASK_BITNR				0x3fff
#define MEDUSA_EVTYPE_NOTTRIGGERED		MASK_BITNR
#define MEDUSA_EVTYPE_TRIGGEREDATSUBJECT	0x0000	/* for the beauty of L2 */
#define MEDUSA_EVTYPE_TRIGGEREDATOBJECT		0x8000

#define MEDUSA_EVTYPE_TRIGGEREDBYSUBJECTBIT	0x0000	/* for the beauty of L2 */
#define MEDUSA_EVTYPE_TRIGGEREDBYOBJECTBIT	0x4000

#define MEDUSA_ACCTYPE_NOTTRIGGERED		MEDUSA_EVTYPE_NOTTRIGGERED
#define MEDUSA_ACCTYPE_TRIGGEREDATSUBJECT (MEDUSA_EVTYPE_TRIGGEREDATSUBJECT | \
				MEDUSA_EVTYPE_TRIGGEREDBYSUBJECTBIT)
#define MEDUSA_ACCTYPE_TRIGGEREDATOBJECT (MEDUSA_EVTYPE_TRIGGEREDATOBJECT | \
				MEDUSA_EVTYPE_TRIGGEREDBYOBJECTBIT)

/* internal macro */
#define ___MEDUSA_EVENTOP(evname, kobjptr, OP, WHAT, WHERE) \
		OP((kobjptr)->med_ ## WHERE.act, MED_EVTYPEOF(evname).WHAT)

/* is the event monitored (at object) ? */
#define MEDUSA_MONITORED_EVENT_O(evname, kobjptr) \
	___MEDUSA_EVENTOP(evname, kobjptr, act_testbit, bitnr & MASK_BITNR, object)
/* is the event monitored (at subject) ? */
#define MEDUSA_MONITORED_EVENT_S(evname, kobjptr) \
	___MEDUSA_EVENTOP(evname, kobjptr, act_testbit, bitnr, subject)
/* set the event monitoring at object */
#define MEDUSA_MONITOR_EVENT_O(evname, kobjptr) \
	___MEDUSA_EVENTOP(evname, kobjptr, act_setbit, bitnr & MASK_BITNR, object)
/* set the event monitoring at subject */
#define MEDUSA_MONITOR_EVENT_S(evname, kobjptr) \
	___MEDUSA_EVENTOP(evname, kobjptr, act_setbit, bitnr, subject)
/* unset the event monitoring at object */
#define MEDUSA_UNMONITOR_EVENT_O(evname, kobjptr) \
	___MEDUSA_EVENTOP(evname, kobjptr, act_clearbit, bitnr & MASK_BITNR, object)
/* unset the event monitoring at subject */
#define MEDUSA_UNMONITOR_EVENT_S(evname, kobjptr) \
	___MEDUSA_EVENTOP(evname, kobjptr, act_clearbit, bitnr, subject)

#define MEDUSA_MONITORED_ACCESS_O(evname, kobjptr) \
		MEDUSA_MONITORED_EVENT_O(evname, kobjptr)
#define MEDUSA_MONITORED_ACCESS_S(evname, kobjptr) \
		MEDUSA_MONITORED_EVENT_S(evname, kobjptr)
#define MEDUSA_MONITOR_ACCESS_O(evname, kobjptr) \
		MEDUSA_MONITOR_EVENT_O(evname, kobjptr)
#define MEDUSA_MONITOR_ACCESS_S(evname, kobjptr) \
		MEDUSA_MONITOR_EVENT_S(evname, kobjptr)
#define MEDUSA_UNMONITOR_ACCESS_O(evname, kobjptr) \
		MEDUSA_UNMONITOR_EVENT_O(evname, kobjptr)
#define MEDUSA_UNMONITOR_ACCESS_S(evname, kobjptr) \
		MEDUSA_UNMONITOR_EVENT_S(evname, kobjptr)

	void *cinfo; /* l4 hint: must be able to hold pointer for linked list of registered events */
#ifdef CONFIG_MEDUSA_PROFILING
	unsigned long long l2_to_l4;
	unsigned long long l4_to_l2;
#endif

	/* l2-defined data */
	char name[MEDUSA_EVNAME_MAX];		/* string: event name */
	struct medusa_kclass_s *arg_kclass[2];	/* kclasses of arguments */
	char arg_name[2][MEDUSA_ATTRNAME_MAX];	/* names of arguments */
	unsigned int event_size;		/* sizeof(event) */
	struct medusa_attribute_s *attr;	/* attributes */
};

#ifdef CONFIG_MEDUSA_PROFILING
#define MEDUSA_DEFAULT_EVTYPE_HEADER \
	NULL,	/* register_evtype */ \
	0 /* bitnr */, \
	0 /* cinfo */, \
	0, 0
#else
#define MEDUSA_DEFAULT_EVTYPE_HEADER \
	NULL,	/* register_evtype */ \
	0 /* bitnr */, \
	0 /* cinfo */
#endif
#define MEDUSA_DEFAULT_ACCTYPE_HEADER MEDUSA_DEFAULT_EVTYPE_HEADER

#define MED_EVTYPE(structname, evtypename, s1name, arg1name, s2name, arg2name) \
	struct medusa_evtype_s (MED_EVTYPEOF(structname)) = {		\
		MEDUSA_DEFAULT_ACCTYPE_HEADER,				\
		(evtypename),						\
		{ &MED_KCLASSOF(s1name), &MED_KCLASSOF(s2name) },	\
		{ (arg1name), (arg2name) },				\
		sizeof(struct structname),				\
		MED_ATTRSOF(structname)					\
	}
#define MED_ACCTYPE(structname, acctypename, s1name, arg1name, s2name, arg2name) \
	MED_EVTYPE(structname, acctypename, s1name, arg1name, s2name, arg2name)

/* this is the access header - use it at the beginning of l2 structures */
#define MEDUSA_ACCESS_HEADER \
	struct medusa_evtype_s *evtype_id
/* used by l3 and l4 to easily access the header of l2 structures */
struct medusa_event_s {
	MEDUSA_ACCESS_HEADER;
	unsigned char data[0];
};

#endif

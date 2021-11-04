/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_MODEL_H
#define _MEDUSA_MODEL_H

#include "l3/config.h"
#include "l3/vs_model.h"

#define MAGIC_NOT_MONITORED (-1L)

extern int medusa_authserver_magic;

struct s_cinfo_t {
	u_int64_t data[1];
};

struct o_cinfo_t {
	u_int64_t data[1];
};

struct medusa_object_s {
	struct vs_t vs;		/* virt. spaces of this object */
	struct act_t act;	/* actions on this object, which are reported to L4 */
	struct o_cinfo_t cinfo;	/* l4 hint */
	int magic;		/* whether this piece of crap is valid */
};

struct medusa_subject_s {
	struct vs_t vsr;	/* which vs I can read from */
	struct vs_t vsw;	/* which vs I can write to */
	struct vs_t vss;	/* which vs I can see */
	struct act_t act;	/* which actions of me are monitored. this may slig.. */
	struct s_cinfo_t cinfo;	/* l4 hint */
};

static inline void init_med_object(struct medusa_object_s *med_object)
{
	// Allow all VSs
	vs_set(med_object->vs);
	// Set monitoring of all acctypes
	act_set(med_object->act);
	med_object->cinfo.data[0] = 0;
	med_object->magic = 0;
}

static inline void unmonitor_med_object(struct medusa_object_s *med_object)
{
	// Allow all VSs
	vs_set(med_object->vs);
	// Clear monitoring of all acctypes
	act_clear(med_object->act);
}

static inline void init_med_subject(struct medusa_subject_s *med_subject)
{
	// Allow abilities to all VSs
	vs_set(med_subject->vss);
	vs_set(med_subject->vsr);
	vs_set(med_subject->vsw);
	// Set monitoring of all acctypes
	act_set(med_subject->act);
	med_subject->cinfo.data[0] = 0;
}

static inline void unmonitor_med_subject(struct medusa_subject_s *med_subject)
{
	// Allow abilities to all VSs
	vs_set(med_subject->vss);
	vs_set(med_subject->vsr);
	vs_set(med_subject->vsw);
	// Clear monitoring of all acctypes
	act_clear(med_subject->act);
}

static inline int _is_med_magic_valid(struct medusa_object_s *med_object, int expected_magic)
{
	return (med_object->magic == MAGIC_NOT_MONITORED) || (med_object->magic == expected_magic);
}

static inline int is_med_magic_valid(struct medusa_object_s *med_object)
{
	return _is_med_magic_valid(med_object, medusa_authserver_magic);
}

static inline void _med_magic_validate(struct medusa_object_s *med_object, int magic)
{
	med_object->magic = magic;
}

static inline void med_magic_validate(struct medusa_object_s *med_object)
{
	_med_magic_validate(med_object, medusa_authserver_magic);
}

static inline void med_magic_not_monitored(struct medusa_object_s *med_object)
{
	_med_magic_validate(med_object, MAGIC_NOT_MONITORED);
}

static inline void med_magic_invalidate(struct medusa_object_s *med_object)
{
	med_object->magic = 0;
}

#endif /* _MEDUSA_MODEL_H */

/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_MODEL_H
#define _MEDUSA_MODEL_H

#include "l3/config.h"
#include "l3/vs_model.h"

#define MAGIC_NOT_MONITORED U64_MAX

extern u64 medusa_authserver_magic;

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
	u64 magic;		/* cache generation or MAGIC_NOT_MONITORED */
};

struct medusa_subject_s {
	struct vs_t vsr;	/* which vs I can read from */
	struct vs_t vsw;	/* which vs I can write to */
	struct vs_t vss;	/* which vs I can see */
	struct act_t act;	/* which actions of me are monitored. this may slig.. */
	struct s_cinfo_t cinfo;	/* l4 hint */
};

static inline bool medusa_vs_access_allowed(const struct medusa_subject_s *subject,
					    const struct medusa_object_s *object,
					    unsigned int requested)
{
	if ((requested & MEDUSA_VS_SEE) &&
	    !vs_intersects(subject->vss, object->vs))
		return false;
	if ((requested & MEDUSA_VS_READ) &&
	    !vs_intersects(subject->vsr, object->vs))
		return false;
	if ((requested & MEDUSA_VS_WRITE) &&
	    !vs_intersects(subject->vsw, object->vs))
		return false;
	return true;
}

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

static inline bool is_med_magic_monitored(struct medusa_object_s *med_object)
{
	return med_object->magic != MAGIC_NOT_MONITORED;
}

static inline bool is_med_magic_valid(struct medusa_object_s *med_object)
{
	return (med_object->magic == MAGIC_NOT_MONITORED) ||
		(med_object->magic == READ_ONCE(medusa_authserver_magic));
}

static inline void _med_magic_set(struct medusa_object_s *med_object, u64 magic,
				  bool force)
{
	// Do not change magic of not monitored tasks, if not forced
	if (!force && med_object->magic == MAGIC_NOT_MONITORED)
		return;
	med_object->magic = magic;
}

static inline void med_magic_validate(struct medusa_object_s *med_object)
{
	_med_magic_set(med_object, READ_ONCE(medusa_authserver_magic), false);
}

static inline void med_magic_not_monitored(struct medusa_object_s *med_object)
{
	_med_magic_set(med_object, MAGIC_NOT_MONITORED, false);
}

static inline void med_magic_invalidate_force(struct medusa_object_s *med_object)
{
	_med_magic_set(med_object, 0, true);
}

static inline void med_magic_invalidate(struct medusa_object_s *med_object)
{
	_med_magic_set(med_object, 0, false);
}

#endif /* _MEDUSA_MODEL_H */

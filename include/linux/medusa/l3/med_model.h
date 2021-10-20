#ifndef _MEDUSA_MODEL_H
#define _MEDUSA_MODEL_H

#include <linux/medusa/l3/config.h>
#include <linux/medusa/l3/vs_model.h>

extern int medusa_authserver_magic;

typedef struct {
	u_int64_t data[1];
} s_cinfo_t, o_cinfo_t;

/* cinfo_t is at kclass and events at l4
   must be able to hold pointer for linked lists of registered kclass and events */
typedef void* cinfo_t;

struct medusa_object_s {
	vs_t vs;	/* virt. spaces of this object */
	act_t act;	/* actions on this object, which are reported to L4 */
	o_cinfo_t cinfo;/* l4 hint */
	int magic;	/* whether this piece of crap is valid */
};

struct medusa_subject_s {
	vs_t vsr;	/* which vs I can read from */
	vs_t vsw;	/* which vs I can write to */
	vs_t vss;	/* which vs I can see */
	act_t act;	/* which actions of me are monitored. this may slig.. */
	s_cinfo_t cinfo;/* l4 hint */
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
	return med_object->magic == expected_magic;
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

static inline void med_magic_invalidate(struct medusa_object_s *med_object)
{
	med_object->magic = 0;
}

#endif /* _MEDUSA_MODEL_H */

#ifndef _MEDUSA_MODEL_H
#define _MEDUSA_MODEL_H

#include <linux/medusa/l3/config.h>
#include <linux/medusa/l3/vsmodel.h>

extern int medusa_authserver_magic;

#define MEDUSA_OBJECT_VARS struct medusa_object_s med_object
#define MEDUSA_SUBJECT_VARS struct medusa_subject_s med_subject

#define ALL_VS_ALLOWED 0xffffffff

typedef struct {
	u_int64_t data[1];
} s_cinfo_t, o_cinfo_t;

/* cinfo_t is at kclass and events at l4
   must be able to hold pointer for linked lists of registered kclass and events */
typedef void* cinfo_t;

typedef u_int32_t act_t;

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

#define UNMONITOR_MEDUSA_OBJECT_VARS(ptr) \
	do { /* don't touch, unless you REALLY know what you are doing. */ \
		int i;							\
		for (i=0; i<(CONFIG_MEDUSA_VS+31)/32; i++)		\
			(ptr)->med_object.vs.vspack[i] = 0xffffffff;	\
		(ptr)->med_object.act = 0;				\
	} while (0)

#define UNMONITOR_MEDUSA_SUBJECT_VARS(ptr) \
	do { /* don't touch, unless you REALLY know what you are doing. */ \
		int i;							\
		for (i=0; i<(CONFIG_MEDUSA_VS+31)/32; i++)		\
			(ptr)->med_subject.vss.vspack[i] =		\
			(ptr)->med_subject.vsr.vspack[i] =		\
			(ptr)->med_subject.vsw.vspack[i] =		\
				 0xffffffff;				\
		(ptr)->med_subject.act = 0;				\
	} while (0)

#define MED_MAGIC_VALID(pointer) \
	((pointer)->med_object.magic == medusa_authserver_magic)

#define MED_MAGIC_VALIDATE(pointer) \
	do { \
		(pointer)->med_object.magic = medusa_authserver_magic; \
	} while (0)
#define MED_MAGIC_INVALIDATE(pointer) \
	do { \
		(pointer)->med_object.magic = 0; \
	} while (0)

static inline void init_med_object(struct medusa_object_s *med_object)
{
	int i;
	for (i = 0; i < VSPACK_LENGTH; i++) {
		med_object->vs.vspack[i] = 0xffffffff;
	}
	med_object->act = 0xffffffff;
	med_object->cinfo.data[0] = 0;
	med_object->magic = 0;
}

static inline void unmonitor_med_object(struct medusa_object_s *med_object)
{
	int i;
	for (i = 0; i < VSPACK_LENGTH; i++) {
		med_object->vs.vspack[i] = ALL_VS_ALLOWED;
	}
	med_object->act = 0;
}

static inline void init_med_subject(struct medusa_subject_s *med_subject)
{
	int i;
	for (i = 0; i < VSPACK_LENGTH; i++) {
		med_subject->vss.vspack[i] = ALL_VS_ALLOWED;
		med_subject->vsr.vspack[i] = ALL_VS_ALLOWED;
		med_subject->vsw.vspack[i] = ALL_VS_ALLOWED;
	}
	med_subject->act = 0xffffffff;
	med_subject->cinfo.data[0] = 0;
}

static inline void unmonitor_med_subject(struct medusa_subject_s *med_subject)
{
	int i;
	for(i = 0; i < VSPACK_LENGTH; i++) {
		med_subject->vss.vspack[i] = ALL_VS_ALLOWED;
		med_subject->vsr.vspack[i] = ALL_VS_ALLOWED;
		med_subject->vsw.vspack[i] = ALL_VS_ALLOWED;
	}
	med_subject->act = 0;
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

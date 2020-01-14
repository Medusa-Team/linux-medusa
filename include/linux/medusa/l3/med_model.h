#ifndef _MEDUSA_MODEL_H
#define _MEDUSA_MODEL_H

#include <linux/medusa/l3/vs_model.h>

extern int medusa_authserver_magic;

#define ALL_VS_ALLOWED 0xffffffff
#define MEDUSA_OBJECT struct medusa_object_s med_object
#define MEDUSA_SUBJECT struct medusa_subject_s med_subject

/* cinfo_t is at kclass and events at l4 must be able to hold pointer for linked lists of registered kclass and events */
typedef void* cinfo_t;
typedef u_int32_t act_t;

/* {s|o}_cinfo_t is at each *S*ubject or *O*bject for internal use of auth server 
   for Constable should be able to hold pointer(s) on 64-bit and 32-bit arch, too */
typedef struct {
	u_int64_t data[1];
} s_cinfo_t, o_cinfo_t;

struct medusa_object_s {
	vs_t vs;	/* virt. spaces of this object */
	act_t act;	/* actions on this object, which are reported to L4 */
	o_cinfo_t cinfo;/* l4 hint */
	int magic;	/* whether this object is valid */
};

struct medusa_subject_s {
	vs_t vsr;	/* which vs I can read from */
	vs_t vsw;	/* which vs I can write to */
	vs_t vss;	/* which vs I can see */
	act_t act;	/* which actions of this subject are monitored */
	s_cinfo_t cinfo;/* l4 hint */
};

static inline void init_med_object(struct medusa_object_s *med_object)
{
	int i;
	for (i = 0; i < VS_LENGTH; i++) {
		med_object->vs.vspack[i] = ALL_VS_ALLOWED;
	}
	med_object->act = ALL_VS_ALLOWED;
	med_object->cinfo.data[0] = 0;
	med_object->magic = 0;
}

static inline void unmonitor_med_object(struct medusa_object_s *med_object)
{
	int i;
	for (i = 0; i < VS_LENGTH; i++) {
		med_object->vs.vspack[i] = ALL_VS_ALLOWED;
	}
	med_object->act = 0;
}

static inline void init_med_subject(struct medusa_subject_s *med_subject)
{
	int i;
	for (i = 0; i < VS_LENGTH; i++) {
		med_subject->vss.vspack[i] = ALL_VS_ALLOWED;
		med_subject->vsr.vspack[i] = ALL_VS_ALLOWED;
		med_subject->vsw.vspack[i] = ALL_VS_ALLOWED;
	}
	med_subject->act = ALL_VS_ALLOWED;
	med_subject->cinfo.data[0] = 0;
}

static inline void unmonitor_med_subject(struct medusa_subject_s *med_subject)
{
	int i;
	for (i = 0; i < VS_LENGTH; i++) {
		med_subject->vss.vspack[i] = ALL_VS_ALLOWED;
		med_subject->vsr.vspack[i] = ALL_VS_ALLOWED;
		med_subject->vsw.vspack[i] = ALL_VS_ALLOWED;
	}
	med_subject->act = 0;
}

static inline int is_med_object_valid(struct medusa_object_s med_object)
{
	return med_object.magic == medusa_authserver_magic;
}

static inline void med_magic_validate(struct medusa_object_s *med_object)
{
	med_object->magic = medusa_authserver_magic;
}

static inline void med_magic_invalidate(struct medusa_object_s *med_object)
{
	med_object->magic = 0;
}

#endif /* _MEDUSA_MODEL_H */

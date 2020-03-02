#ifndef _VSMODEL_H
#define _VSMODEL_H

#include <linux/medusa/l3/config.h>
#include <linux/bitmap.h>

#define _VS(X)	((X)->vs)
#define _VSR(X)	((X)->vsr)
#define _VSW(X)	((X)->vsw)
#define _VSS(X)	((X)->vss)

#define VS(X) _VS(&((X)->med_object))
#define VSR(X) _VSR(&((X)->med_subject))
#define VSW(X) _VSW(&((X)->med_subject))
#define VSS(X) _VSS(&((X)->med_subject))

#if CONFIG_MEDUSA_VS <= 32
	#define VSPACK_LENGTH 1
#else
	#define VSPACK_LENGTH (1 + (CONFIG_MEDUSA_VS-1)/32)
#endif

#define VS_TOTAL_BITS (VSPACK_LENGTH*32)

typedef struct { u_int32_t vspack[VSPACK_LENGTH]; } vs_t;

static inline int vs_intersects(vs_t X, vs_t Y)
{
	return bitmap_intersects((uintptr_t*)X.vspack,
				(uintptr_t*)Y.vspack, VS_TOTAL_BITS);
}

#endif /* VSMODEL_H */

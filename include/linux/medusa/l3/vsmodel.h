#ifndef _VSMODEL_H
#define _VSMODEL_H

#include <linux/medusa/l3/config.h>

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
	#define VSPACK_LENGTH 1 + (CONFIG_MEDUSA_VS-1)/32
#endif

typedef struct { u_int32_t vspack[VSPACK_LENGTH]; } vs_t;

static inline int VS_INTERSECT(vs_t X, vs_t Y)
{
	int i;
	for (i=0; i<(CONFIG_MEDUSA_VS+31)/32; i++)
		if (X.vspack[i] & Y.vspack[i])
			return 1;
	return 0;
}

#endif /* VSMODEL_H */

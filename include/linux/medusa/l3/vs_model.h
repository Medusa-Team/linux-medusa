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

typedef struct { DECLARE_BITMAP(pack, CONFIG_MEDUSA_VS); } vs_t;
typedef struct { DECLARE_BITMAP(pack, CONFIG_MEDUSA_ACT); } act_t;

#define vs_intersects(X, Y) \
	bitmap_intersects(X.pack, Y.pack, CONFIG_MEDUSA_VS)
#define vs_set(X) \
	bitmap_set(X.pack, 0, CONFIG_MEDUSA_VS)
#define vs_setbit(X, NR) \
	bitmap_set(X.pack, NR, 1)
#define vs_clear(X) \
	bitmap_clear(X.pack, 0, CONFIG_MEDUSA_VS)
#define vs_clearbit(X, NR) \
	bitmap_clear(X.pack, NR, 1)
#define vs_complement(DST, SRC) \
	bitmap_complement(DST.pack, SRC.pack, CONFIG_MEDUSA_VS)

#define act_set(X) \
	bitmap_set(X.pack, 0, CONFIG_MEDUSA_ACT)
#define act_clear(X) \
	bitmap_clear(X.pack, 0, CONFIG_MEDUSA_ACT)

#endif /* VSMODEL_H */

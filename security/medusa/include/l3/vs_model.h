/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _VSMODEL_H
#define _VSMODEL_H

#include <linux/bitmap.h>
#include "l3/config.h"

#define _VS(X)	((X)->vs)
#define _VSR(X)	((X)->vsr)
#define _VSW(X)	((X)->vsw)
#define _VSS(X)	((X)->vss)

#define VS(X) _VS(&((X)->med_object))
#define VSR(X) _VSR(&((X)->med_subject))
#define VSW(X) _VSW(&((X)->med_subject))
#define VSS(X) _VSS(&((X)->med_subject))

struct vs_t { DECLARE_BITMAP(pack, CONFIG_MEDUSA_VS); };
struct act_t { DECLARE_BITMAP(pack, CONFIG_MEDUSA_ACT); };

/* VS bitmap */

#define vs_intersects(X, Y) \
	bitmap_intersects((X).pack, (Y).pack, CONFIG_MEDUSA_VS)
#define vs_set(X) \
	bitmap_set((X).pack, 0, CONFIG_MEDUSA_VS)
#define vs_clear(X) \
	bitmap_clear((X).pack, 0, CONFIG_MEDUSA_VS)
#define vs_complement(DST, SRC) \
	bitmap_complement((DST).pack, (SRC).pack, CONFIG_MEDUSA_VS)

static inline void vs_setbit(struct vs_t vs, int bitnr)
{
	if (!WARN_ONCE(bitnr >= CONFIG_MEDUSA_VS, "medusa: %s: bitnr overflow", __func__))
		set_bit(bitnr, vs.pack);
}

static inline void vs_clearbit(struct vs_t vs, int bitnr)
{
	if (!WARN_ONCE(bitnr >= CONFIG_MEDUSA_VS, "medusa: %s: bitnr overflow", __func__))
		clear_bit(bitnr, vs.pack);
}

/* ACT bitmap */

#define act_set(X) \
	bitmap_set((X).pack, 0, CONFIG_MEDUSA_ACT)
#define act_clear(X) \
	bitmap_clear((X).pack, 0, CONFIG_MEDUSA_ACT)

static inline void act_setbit(struct act_t act, int bitnr)
{
	if (!WARN_ONCE(bitnr >= CONFIG_MEDUSA_ACT, "medusa: %s: bitnr overflow", __func__))
		set_bit(bitnr, act.pack);
}

static inline void act_clearbit(struct act_t act, int bitnr)
{
	if (!WARN_ONCE(bitnr >= CONFIG_MEDUSA_ACT, "medusa: %s: bitnr overflow", __func__))
		clear_bit(bitnr, act.pack);
}

static inline int act_testbit(struct act_t act, int bitnr)
{
	if (WARN_ONCE(bitnr >= CONFIG_MEDUSA_ACT, "medusa: %s: bitnr overflow", __func__))
		return 0;
	return test_bit(bitnr, act.pack);
}

#endif /* VSMODEL_H */

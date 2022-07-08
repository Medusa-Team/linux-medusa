/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_CACHE_H
#define _MEDUSA_CACHE_H

struct kmem_cache **alloc_med_cache_array(size_t size);
int med_cache_register(size_t size);
void *med_cache_alloc_size(size_t size);
void med_cache_free(void *mem);

#endif

// SPDX-License-Identifier: GPL-2.0

/*
 * Medusa L4 memory cache interface
 *
 * (C) 2018, 2020 Roderik Ploszek <roderik.ploszek@gmail.com>
 */

#include <linux/slab.h>

#define FAT_PTR_OFFSET_TYPE uint32_t
#define FAT_PTR_OFFSET sizeof(FAT_PTR_OFFSET_TYPE)
/* Max size hint for the med_cache_array. Set it to the largest expected value,
 * so it doesn't have to reallocate. Value 15 means that maximum cache size is
 * 2^14 B before it has to be reallocated.
 */
#define CACHE_ARRAY_SIZE_HINT 15

/* Array for memory caches */
int cache_array_size;
static struct kmem_cache **med_cache_array;

/**
 * _log2_rounded_up() - Compute binary logarithm rounded up.
 */
static inline int _log2_rounded_up(int in)
{
	int ret = 1;

	in--;
	while (in >>= 1)
		ret++;
	return ret;
}

static inline int get_mem_cache_index(size_t size)
{
	return _log2_rounded_up(FAT_PTR_OFFSET + size);
}

/**
 * med_cache_create() - Create a memory cache on a given index.
 *
 * If there is not enough space in the array, reallocate it.
 * If a cache already exists, do nothing.
 */
static struct kmem_cache *med_cache_create(size_t index)
{
	if (index >= cache_array_size)
		return NULL;
	if (med_cache_array[index])
		return med_cache_array[index];
	med_cache_array[index] = kmem_cache_create("med_cache",
			1 << index,
			0,
			SLAB_HWCACHE_ALIGN | SLAB_PANIC,
			NULL);
	return med_cache_array[index];
}

/**
 * alloc_med_cache_array() - Allocate an array for memory caches and initialize
 * it with nulls.
 */
struct kmem_cache **alloc_med_cache_array(size_t size)
{
	int i;

	if (med_cache_array)
		return med_cache_array;
	med_cache_array = (struct kmem_cache **)
		kmalloc_array(size, sizeof(struct kmem_cache *), GFP_KERNEL);
	if (med_cache_array) {
		for (i = 0; i < size; i++)
			med_cache_array[i] = NULL;
		cache_array_size = size;
	}
	return med_cache_array;
}

/**
 * realloc_med_cache_array() - Reallocate the memory cache array for a given
 * size.
 *
 * If the size is smaller or the same as the existing array, do nothing.
 */
static struct kmem_cache **realloc_med_cache_array(size_t size)
{
	int i;
	struct kmem_cache **new_cache_array;

	if (size <= cache_array_size)
		return med_cache_array;
	new_cache_array = (struct kmem_cache **)
		krealloc(med_cache_array, sizeof(struct kmem_cache *) * size, GFP_KERNEL);
	if (new_cache_array) {
		for (i = cache_array_size; i < size; i++)
			med_cache_array[i] = NULL;
		cache_array_size = size;
	}
	return new_cache_array;
}

/**
 * med_cache_register() - Create a memory cache for a given size if it doesn't
 * exist.
 *
 * Note: Caches are registered from two places - user_open() in chardev.c and
 * med_register_kclass() in registry.c. Unregistering is not supported as it's
 * assumed the caches will be used until shutdown.
 */
int med_cache_register(size_t size)
{
	int idx;

	idx = get_mem_cache_index(size);
	if (idx >= cache_array_size)
		if (!realloc_med_cache_array(idx))
			return -ENOMEM;
	if (!med_cache_array[idx])
		if (!med_cache_create(idx))
			return -ENOMEM;
	return 0;
}

/**
 * med_cache_alloc_index() - Allocate memory from a memory pool chosen by the
 * index argument.
 * @index: Index of memory cache to use.
 *
 * Warning - selected index has to take fat pointer offset into account!
 *
 * Return: Pointer to allocated memory or %NULL in case of an error
 */
static void *med_cache_alloc_index(size_t index)
{
	void *ret;

	ret = kmem_cache_alloc(med_cache_array[index], GFP_NOWAIT);
	if (!ret)
		return NULL;

	*((FAT_PTR_OFFSET_TYPE *)ret) = index;
	ret = ((FAT_PTR_OFFSET_TYPE *)ret) + 1;
	return ret;
}

/**
 * med_cache_alloc_size() - Allocate memory from a memory pool chosen by the
 * size argument.
 */
void *med_cache_alloc_size(size_t size)
{
	int idx;

	idx = get_mem_cache_index(size);
	return med_cache_alloc_index(idx);
}

/**
 * med_cache_free() - Free previously allocated memory.
 */
void med_cache_free(void *mem)
{
	int idx;

	mem = ((FAT_PTR_OFFSET_TYPE *)mem) - 1;
	idx = *((FAT_PTR_OFFSET_TYPE *)mem);
	kmem_cache_free(med_cache_array[idx], mem);
}

/**
 * init_med_cache() - Initialize the array of memory caches.
 */
static int __init init_med_cache(void)
{
	if (!alloc_med_cache_array(CACHE_ARRAY_SIZE_HINT))
		return -ENOMEM;
	return 0;
}
fs_initcall(init_med_cache);

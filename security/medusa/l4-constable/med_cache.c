/*
 * Medusa L4 memory cache interface
 *
 * (C) 2018, 2020 Roderik Ploszek <roderik.ploszek@gmail.com>
 */

#include <linux/slab.h>

#define FAT_PTR_OFFSET_TYPE uint32_t
#define FAT_PTR_OFFSET sizeof(FAT_PTR_OFFSET_TYPE)

// Array for memory caches
int cache_array_size = 0;
static struct kmem_cache **med_cache_array;

/**
 * Computes binary logarithm rounded up
 */
static inline int get_log_index(int in) {
	int ret = 1;
	in--;
	while (in >>= 1)
		ret++;
	return ret;
}

/**
 * Create a memory cache on a given index.
 * If there is not enough space in the array, reallocate it.
 * If a cache already exists, do nothing.
 */
static struct kmem_cache* med_cache_create(size_t index) {
	if (index >= cache_array_size)
		return NULL;
	if (med_cache_array[index])
		return med_cache_array[index];
	med_cache_array[index] = kmem_cache_create("med_cache",
			1 << index,
			0,
			SLAB_HWCACHE_ALIGN,
			NULL);
	return med_cache_array[index];
}

/**
 * Allocate an array for memory caches and initialize it with nulls.
 */
struct kmem_cache** alloc_med_cache_array(size_t size) {
	int i;
	if (med_cache_array)
		return med_cache_array;
	med_cache_array = (struct kmem_cache**)
		kmalloc(sizeof(struct kmem_cache*) * size, GFP_KERNEL);
	if (med_cache_array) {
		for (i = 0; i < size; i++)
			med_cache_array[i] = NULL;
		cache_array_size = size;
	}
	return med_cache_array;
}

/**
 * Reallocate the memory cache array for a given size.
 * If the size is smaller or the same as the existing array, do nothing.
 */
static struct kmem_cache** realloc_med_cache_array(size_t size) {
	int i;
	struct kmem_cache** new_cache_array;
	if (size <= cache_array_size)
		return med_cache_array;
	new_cache_array = (struct kmem_cache**)
		krealloc(med_cache_array, sizeof(struct kmem_cache*) * size, GFP_KERNEL);
	if (new_cache_array) {
		for (i = cache_array_size; i < size; i++)
			med_cache_array[i] = NULL;
		cache_array_size = size;
	}
	return new_cache_array;
}

/**
 * Create a memory cache for a given size if it doesn't exist.
 */
int med_cache_register(size_t size) {
	int log;
	size += FAT_PTR_OFFSET;
	log = get_log_index(size);
	if (log >= cache_array_size)
		if (!realloc_med_cache_array(log))
			return -ENOMEM;
	if (!med_cache_array[log])
		if (!med_cache_create(log))
			return -ENOMEM;
	return 0;
}

/**
 * Allocate memory from a memory pool chosen by the index argument.
 * Warning - selected index has to take fat pointer offset into account!
 */
static void* med_cache_alloc_index(size_t index) {
	void* ret;
	ret = kmem_cache_alloc(med_cache_array[index], GFP_NOWAIT);
	*((FAT_PTR_OFFSET_TYPE*)ret) = index;
	ret = ((FAT_PTR_OFFSET_TYPE*)ret) + 1;
	return ret;
}

/**
 * Allocate memory from a memory pool chosen by the size argument.
 */
void* med_cache_alloc_size(size_t size) {
	int log;
	size += FAT_PTR_OFFSET;
	log = get_log_index(size);
	return med_cache_alloc_index(log);
}

/**
 * Free previously allocated memory.
 */
void med_cache_free(void* mem) {
	int log;
	mem = ((FAT_PTR_OFFSET_TYPE*)mem) - 1;
	log = *((FAT_PTR_OFFSET_TYPE*)mem);
	kmem_cache_free(med_cache_array[log], mem);
}

/**
 * Destroy all memory caches in the array.
 */
void med_cache_destroy(void) {
	int i;
	for(i = 0; i < cache_array_size; i++) {
		if (med_cache_array[i])
			kmem_cache_destroy(med_cache_array[i]);
	}
}

/**
 * Free the array of memory caches.
 */
void free_med_cache_array(void) {
	med_cache_destroy();
	kfree(med_cache_array);
	med_cache_array = NULL;
}

/**
 * Initialize the array of memory caches.
 */
static int __init init_med_cache(void) {
	if (!alloc_med_cache_array(15))
		return -ENOMEM;
	return 0;
}
fs_initcall(init_med_cache);

/**
 * @file kflat_bsp.h
 * @author Pawel Wieczorek (p.wieczorek@samsung.com)
 * @brief Platform specific code for KFLAT (Kernel Flattening) module
 * 
 */

#ifndef KFLAT_BSP_H
#define KFLAT_BSP_H

#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/stop_machine.h>
#include <linux/time.h>
#include <linux/cpufreq.h>
#include <linux/smp.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/interval_tree_generic.h>

#include "kdump.h"


/* Logging */
void kflat_dbg_buf_clear(void);
void kflat_dbg_printf(const char* fmt, ...);

#define kflat_fmt(fmt) 		"kflat: " fmt

#define FLATTEN_LOG_ERROR(fmt, ...)		printk_ratelimited(KERN_ERR kflat_fmt(fmt), ##__VA_ARGS__)
#define FLATTEN_LOG_INFO(fmt, ...)		printk_ratelimited(KERN_INFO kflat_fmt(fmt), ##__VA_ARGS__)
#define FLATTEN_LOG_DEBUG(fmt, ...)		kflat_dbg_printf(fmt, ##__VA_ARGS__)
#define FLATTEN_LOG_CLEAR()             kflat_dbg_buf_clear()

/* Memory allocation */
#define FLATTEN_BSP_ZALLOC(SIZE)        kvzalloc(SIZE, GFP_KERNEL)
#define FLATTEN_BSP_FREE(PTR)           kvfree(PTR)
#define FLATTEN_BSP_VMA_ALLOC(SIZE)		vmalloc(SIZE)
#define FLATTEN_BSP_VMA_FREE(PTR, SIZE) vfree(PTR)

/* Memory validation */
static __used bool _addr_range_valid(void* ptr, size_t size) {
	size_t avail_size;
	avail_size = kdump_test_address(ptr, size);

	if(avail_size == 0)
		return false;
	else if(avail_size >= size)
		return true;
	
	printk_ratelimited(KERN_ERR "kflat: Failed to access %zu bytes of mem@%llx. Only %zu bytes are mapped",
		size, (unsigned long long)ptr, avail_size);
	return false;
}

static inline size_t strmemlen(const char* s) {
	size_t str_size, avail_size, test_size;
	
	// 1. Fast-path. Check whether first 1000 bytes are maped
	//  and look for null-terminator in there
	avail_size = kdump_test_address((void*) s, 1000);
	if(avail_size == 0)
		return 0;

	str_size = strnlen(s, avail_size);
	if(str_size < avail_size)
		// Return string length + null terminator
		return str_size + 1;
	
	// 2. Slow-path. We haven't encountered null-terminator in first
	//  1000 bytes, let's look futher
	test_size = 8 * PAGE_SIZE;
	while(test_size < INT_MAX) {
		size_t partial_size;
		size_t off = avail_size;

		partial_size = kdump_test_address((void*)s + off, test_size);
		if(partial_size == 0)
			return avail_size;
		avail_size += partial_size;
		
		str_size = strnlen(s+off, partial_size);
		if(str_size < partial_size)
			return off + str_size + 1;
		test_size *= 2;
	}

	return avail_size;
}

#define ADDR_VALID(PTR)				kdump_test_address((void*) PTR, 1)
#define ADDR_RANGE_VALID(PTR, SIZE) _addr_range_valid((void*) PTR, SIZE)
#define TEXT_ADDR_VALID(PTR)		ADDR_VALID(PTR)		// TODO: Consider checking +x permission
#define STRING_VALID_LEN(PTR)       strmemlen((const char*) PTR)


/* Misc */
#define EXPORT_FUNC         EXPORT_SYMBOL_GPL
#define FLAT_EXTRACTOR		&(kflat->flat)


#endif /* KFLAT_BSP_H */

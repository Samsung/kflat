/**
 * @file uflat_bsp.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Platform specific code for UFLAT (userspace flattening) module
 * 
 */

#ifndef UFLAT_BSP_H
#define UFLAT_BSP_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>


#define container_of(ptr, type, member) ({			\
  	const __typeof__( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})

#include "rbtree.h"
#include "interval_tree_generic.h"


/*************************************
 * CUSTOMIZE CONFIGURATION FOR UFLAT
 *************************************/
#undef LINEAR_MEMORY_ALLOCATOR
#define LINEAR_MEMORY_ALLOCATOR					0

#undef FLAT_MAX_TIME_NS
#define FLAT_MAX_TIME_NS						(3600 * NSEC_PER_SEC)

/* Funcs decl */
void uflat_info_log_print(const char* fmt, ...);
void uflat_dbg_log_printf(const char* fmt, ...);
void uflat_dbg_log_clear();
bool uflat_test_address_range(struct flat*, void* ptr, size_t size);
bool uflat_test_exec_range(struct flat*, void* ptr) ;
size_t uflat_test_string_len(struct flat*, const char* str);
uintptr_t uflat_image_base_addr(void);


/* Logging */
#define uflat_fmt(fmt) 		            "uflat: " fmt "\n"

#define FLATTEN_LOG_ERROR(fmt, ...)		fprintf(stderr, uflat_fmt(fmt), ##__VA_ARGS__)
#define FLATTEN_LOG_INFO(fmt, ...)		uflat_info_log_print(uflat_fmt(fmt), ##__VA_ARGS__)
#define FLATTEN_LOG_DEBUG(fmt, ...)		uflat_dbg_log_printf(fmt "\n", ##__VA_ARGS__)
#define FLATTEN_LOG_CLEAR()             uflat_dbg_log_clear()

/* Memory allocation */
#define FLATTEN_BSP_ZALLOC(SIZE)        calloc(1, SIZE)
#define FLATTEN_BSP_FREE(PTR)           free(PTR)
#define FLATTEN_BSP_VMA_ALLOC(SIZE)		mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
#define FLATTEN_BSP_VMA_FREE(PTR, SIZE) munmap(PTR, SIZE)

/* Memory validation */
#define ADDR_VALID(PTR)				    uflat_test_address_range(flat, (void*) PTR, 1)
#define ADDR_RANGE_VALID(PTR, SIZE)     uflat_test_address_range(flat, (void*) PTR, SIZE)
#define TEXT_ADDR_VALID(PTR)		    uflat_test_exec_range(flat, PTR)
#define STRING_VALID_LEN(PTR)           uflat_test_string_len(flat, (const char*) PTR)

/* Misc */
#define EXPORT_FUNC(X)         
#define FLAT_EXTRACTOR		            &(uflat->flat)
#define FLATTEN_GET_IMG_BASE_ADDR 		uflat_image_base_addr

#define unlikely                        
#define ALIGN(X, A)                     (((X) + (A - 1)) & ~(A -1))


/* Time measurement */
#define NSEC_PER_MSEC	1000L
#define MSEC_PER_SEC	1000L
#define NSEC_PER_SEC	1000000000L

typedef long long int ktime_t;

static __attribute__((used)) ktime_t ktime_get(void) {
	ktime_t nsec_time;
	struct timespec time;
	
	clock_gettime(CLOCK_MONOTONIC, &time);
	nsec_time = time.tv_nsec + time.tv_sec * NSEC_PER_SEC;
	return nsec_time;
}

/**************************
 *  List implementation 
 * From Linux opensource repository: include/linux/list.h
 * on GPL-2.0 license
 * adapted to work in userspace application
 **************************/
struct list_head {
	struct list_head *next, *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list) {
	list->next = list;
	list->prev = list;
}

static inline int list_empty(const struct list_head *head) {
	return head->next == head;
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)

#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

#define list_entry_is_head(pos, head, member)				\
	(&pos->member == (head))

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
		 !list_entry_is_head(pos, head, member);			\
		 pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
		 !list_entry_is_head(pos, head, member); 			\
		 pos = n, n = list_next_entry(n, member))

static inline void __list_del(struct list_head * prev, struct list_head * next) {
	next->prev = prev;
	prev->next = next;
}


static inline void __list_del_entry(struct list_head *entry) {
	__list_del(entry->prev, entry->next);
}

#define LIST_POISON1        (void*) 0x100
#define LIST_POISON2        (void*) 0x122

static inline void list_del(struct list_head *entry) {
	__list_del_entry(entry);
	entry->next = (struct list_head*) LIST_POISON1;
	entry->prev = (struct list_head*) LIST_POISON2;
}

static inline void __list_add(struct list_head *n,
				  struct list_head *prev,
				  struct list_head *next) {
	next->prev = n;
	n->next = next;
	n->prev = prev;
	prev->next = n;
}

static inline void list_add(struct list_head *n, struct list_head *head) {
	__list_add(n, head, head->next);
}

static inline void list_add_tail(struct list_head *n, struct list_head *head) {
	__list_add(n, head->prev, head);
}


#endif /* UFLAT_BSP_H */

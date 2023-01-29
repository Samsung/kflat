/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KFLAT_H
#define _LINUX_KFLAT_H

#include "kflat_uapi.h"
#include "kdump.h"

#include <linux/mm.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/stop_machine.h>
#include <linux/time.h>
#include <linux/cpufreq.h>
#include <linux/smp.h>


/* KFLAT configuration */
#define LINEAR_MEMORY_ALLOCATOR					1
#define KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE	(256ULL * 1024 * 1024)
#define DEFAULT_ITER_QUEUE_SIZE					(1024 * 1024 * 8)
#define KFLAT_PING_TIME_NS						(1 * NSEC_PER_SEC)
#define KFLAT_MAX_TIME_NS						(8 * NSEC_PER_SEC)


/* Exported structures */
struct flat_node {
	struct rb_node rb;
	uintptr_t start;	/* Start of interval */
	uintptr_t last;	/* Last location _in_ interval */
	uintptr_t __subtree_last;
	struct blstream* storage;
};

struct flatten_pointer {
	struct flat_node* node;
	size_t offset;
};

struct flatten_uninterruptible_arg {
	struct kflat *kflat;
	struct flatten_pointer* __fptr;
	const void* arg;
};

struct flatten_header {
	size_t memory_size;
	size_t ptr_count;
	size_t fptr_count;
	size_t root_addr_count;
	size_t root_addr_extended_count;
	size_t root_addr_extended_size;
	uintptr_t this_addr;
	size_t fptrmapsz;
	size_t mcount;
	uint64_t magic;
};

struct FLCONTROL {
	struct blstream* bhead;
	struct blstream* btail;
	struct rb_root_cached fixup_set_root;
	struct rb_root_cached imap_root;
	struct flatten_header	HDR;
	struct root_addrnode* rhead;
	struct root_addrnode* rtail;
	struct root_addrnode* last_accessed_root;
	size_t root_addr_count;
	int debug_flag;
	unsigned long option;
	void* mem;
};

struct blstream {
	struct blstream* next;
	struct blstream* prev;
	void* data;
	size_t size;
	size_t index;
	size_t alignment;
	size_t align_offset;
};

struct fixup_set_node {
	struct rb_node node;
  	/* Storage area and offset where the original address to be fixed is stored */
	struct flat_node* inode;
	size_t offset;
	/* Storage area and offset where the original address points to */
	struct flatten_pointer* ptr;
};

/* Root address list */
struct root_addrnode {
	struct root_addrnode* next;
	uintptr_t root_addr;
	const char* name;
	size_t index;
	size_t size;
};

struct interval_nodelist {
	struct interval_nodelist* next;
	struct flat_node* node;
};

struct queue_block {
    struct queue_block* next;
    unsigned char data[];
};

struct bqueue {
    size_t block_size;
    size_t size;
    struct queue_block* front_block;
    size_t front_index;
    struct queue_block* back_block;
    size_t back_index;
};

#ifdef CONFIG_ARM64
struct probe_regs {
	union {
    	uint64_t r[30];
		struct {
			// Procedure Call Standard for the ARMv8-A
			uint64_t arg1;		// X0
			uint64_t arg2;		// X1
			uint64_t arg3;		// X2
			uint64_t arg4;		// X3
			uint64_t arg5;		// X4
			uint64_t arg6;		// X5
			uint64_t arg7;		// X6
			uint64_t arg8;		// X7
		} __packed;
	};
    uint64_t NZCV;
    uint64_t lr;
} __packed;

#elif CONFIG_X86_64
struct probe_regs {
    uint64_t EFLAGS;
    union {
        struct {
            uint64_t r[14];			// RAX .. R9
        }  __packed;
        struct {
			// SystemV AMD64 ABI
            uint64_t _unused[2];	// RAX, RBX
			uint64_t arg4;			// RCX
            uint64_t arg3;      	// RDX
            uint64_t arg1;      	// RDI
            uint64_t arg2;      	// RSI
			uint64_t _unused2[1]; 	// RBP
            uint64_t arg5;			// R8
			uint64_t arg6;			// R9
        } __packed;
    };
} __packed;

#endif

struct probe {
	struct mutex		lock;
	int 				triggered;
	uint64_t 			return_ip;
	struct kprobe* 		kprobe;
};

struct kflat_recipe {
	struct list_head 	list;
	struct module*      owner;
	char* 				symbol;
	void 				(*handler)(struct kflat*, struct probe_regs*);
	void				(*pre_handler)(struct kflat*);
};

enum kflat_mode {
	KFLAT_MODE_DISABLED = 0,
	KFLAT_MODE_ENABLED
};

struct kflat {
	/*
	 * Reference counter. We keep one for:
	 *  - opened file descriptor
	 *  - task with enabled coverage (we can't unwire it from another task)
	 */
	atomic_t			refcount;
	/* The lock protects mode, size, area and t. */
	struct mutex		lock;
	enum kflat_mode		mode;
	/* Size of arena (in bytes for KFLAT_MODE_ENABLED). */
	unsigned long		size;
	/* Coverage buffer shared with user space. */
	void				*area;
	/* Task for which we collect coverage, or NULL. */
	struct FLCONTROL 	FLCTRL;
	struct rb_root		root_addr_set;
	int 				errno;
	void*				mpool;
	size_t				mptrindex;
	size_t				msize;
	void*				bqueue_mpool;
	size_t				bqueue_mptrindex;
	size_t				bqueue_msize;

	pid_t				 		pid;
	struct probe		 		probing;
	struct kflat_recipe* 		recipe;
	struct kdump_memory_map 	mem_map;
	int 						debug_flag;
	int 						use_stop_machine;
	int 						skip_function_body;
};

struct flatten_base {};

typedef struct flatten_pointer* (*flatten_struct_t)(struct kflat* kflat, const void*, size_t n, struct bqueue*);
typedef struct flatten_pointer* (*flatten_struct_mixed_convert_t)(struct flatten_pointer*, const struct flatten_base*);

typedef struct flatten_pointer* (*flatten_struct_iter_f)(struct kflat* kflat, const void* _ptr, struct bqueue* __q);
typedef struct flatten_pointer* (*flatten_struct_f)(struct kflat* kflat, const void* _ptr);

typedef void (*flatten_interface_arg_f)(struct kflat* kflat, const void* __arg);

struct recipe_node {
	struct rb_node node;
	char* s;
	flatten_struct_iter_f iterf;
	flatten_struct_f f;
};

struct root_addr_set_node {
	struct rb_node node;
	char* name;
	uintptr_t root_addr;
};

struct ifns_node {
	struct rb_node node;
	char* s;
	flatten_interface_arg_f f;
};

struct flatten_job {
    struct flat_node* node;
    size_t offset;
    size_t size;
    uintptr_t custom_val;
    struct flatten_base* ptr;
    flatten_struct_t fun;
    /* Mixed pointer support */
    const struct flatten_base* fp;
    flatten_struct_mixed_convert_t convert;
};

enum flatten_option {
	KFLAT_OPTION_SILENT = 0x01,
	KFLAT_OPTION_IN_PROGRESS = 0x10,
};

/* Exported functions */
int kflat_recipe_register(struct kflat_recipe* recipe);
int kflat_recipe_unregister(struct kflat_recipe* recipe);
struct kflat_recipe* kflat_recipe_get(char* name);
void kflat_recipe_put(struct kflat_recipe* recipe);


static inline void kflat_bqueue_free(const void* p) {
}

static inline void bqueue_release_memory(struct kflat* kflat) {
	kflat->bqueue_mptrindex = 0;
}

/* Debug printing functions */

void kflat_dbg_buf_clear(void);
void kflat_dbg_printf(const char* fmt, ...);

/* Main interface functions */

void flatten_init(struct kflat* kflat);
int flatten_write(struct kflat* kflat);
int flatten_fini(struct kflat* kflat);
void unflatten_init(void);
int unflatten_read(void* f);
void unflatten_fini(void);
int kflat_linear_memory_realloc(struct kflat* kflat, size_t nsize);

int flatten_write_internal(struct kflat* kflat, size_t* wcounter_p);
struct flatten_pointer* flatten_plain_type(struct kflat* kflat, const void* _ptr, size_t _sz);
int fixup_set_insert(struct kflat* kflat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr);
int fixup_set_insert_force_update(struct kflat* kflat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr);
int fixup_set_insert_fptr(struct kflat* kflat, struct flat_node* node, size_t offset, unsigned long fptr);
int fixup_set_insert_fptr_force_update(struct kflat* kflat, struct flat_node* node, size_t offset, unsigned long fptr);
int fixup_set_reserve_address(struct kflat* kflat, uintptr_t addr);
int fixup_set_reserve(struct kflat* kflat, struct flat_node* node, size_t offset);
int fixup_set_update(struct kflat* kflat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr);
int root_addr_append(struct kflat* kflat, size_t root_addr);
int root_addr_append_extended(struct kflat* kflat, size_t root_addr, const char* name, size_t size);
void* root_pointer_next(void);
void* root_pointer_seq(size_t index);
struct blstream* binary_stream_insert_back(struct kflat* kflat, const void* data, size_t size, struct blstream* where);
struct blstream* binary_stream_insert_front(struct kflat* kflat, const void* data, size_t size, struct blstream* where);
struct blstream* binary_stream_append(struct kflat* kflat, const void* data, size_t size);
struct rb_node *rb_next(const struct rb_node *node);
struct rb_node *rb_prev(const struct rb_node *node);
struct fixup_set_node* fixup_set_search(struct kflat* kflat, uintptr_t v);
void fixup_set_print(struct kflat* kflat);
size_t fixup_set_count(struct kflat* kflat);
size_t fixup_set_fptr_count(struct kflat* kflat);
void fixup_set_destroy(struct kflat* kflat);
int fixup_set_write(struct kflat* kflat, size_t* wcounter_p);
int fixup_set_fptr_write(struct kflat* kflat, size_t* wcounter_p);

size_t root_addr_count(struct kflat* kflat);
struct root_addr_set_node* root_addr_set_search(struct kflat* kflat, const char* name);
int root_addr_set_insert(struct kflat* kflat, const char* name, uintptr_t v);
int root_addr_set_delete(struct kflat* kflat, const char* name);
void root_addr_set_destroy(struct kflat* kflat);
size_t root_addr_set_count(struct kflat* kflat);

int bqueue_init(struct kflat* kflat, struct bqueue* q, size_t block_size);
void bqueue_destroy(struct bqueue* q);
int bqueue_empty(struct bqueue* q);
size_t bqueue_size(struct bqueue* q);
int bqueue_push_back(struct kflat* kflat, struct bqueue* q, const void* m, size_t s);
int bqueue_pop_front(struct bqueue* q, void* m, size_t s);

void flatten_set_option(struct kflat* kflat, int option);
void flatten_clear_option(struct kflat* kflat, int option);

void flatten_run_iter_harness(struct kflat* kflat, struct bqueue* bq);
void flatten_generic(struct kflat* kflat, void* q, struct flatten_pointer* fptr, void* p, size_t el_size, size_t count, flatten_struct_t func_ptr);
struct flat_node* flatten_acquire_node_for_ptr(struct kflat* kflat, const void* _ptr, size_t size);

extern unsigned long (*kflat_lookup_kallsyms_name)(const char* name);
bool flatten_get_object(void* ptr, void** start, void** end);
void* flatten_global_address_by_name(const char* name);


/* Logging */
#undef pr_fmt
#define pr_fmt(fmt) "kflat: " fmt

#define kflat_fmt(fmt) 			"kflat: " fmt
#define flat_errs(fmt,...) 		do { printk_ratelimited(KERN_ERR kflat_fmt(fmt), ##__VA_ARGS__); kflat_dbg_printf(fmt, ##__VA_ARGS__); } while(0)
#define flat_infos(fmt,...) 	do { printk_ratelimited(KERN_INFO kflat_fmt(fmt), ##__VA_ARGS__); kflat_dbg_printf(fmt, ##__VA_ARGS__); } while(0)
#define flat_dbg(fmt, ...)		do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag & 1) kflat_dbg_printf(fmt, ##__VA_ARGS__); } while(0)

#define DBGS(M, ...)						flat_dbg(M, ##__VA_ARGS__)
#define DBGM1(name,a1)						flat_dbg(#name "(" #a1 ")\n")
#define DBGF(name,F,FMT,...)				flat_dbg(#name "(" #F "[" FMT "])\n", ##__VA_ARGS__)
#define DBGOF(name,F,FMT,P,Q)				flat_dbg(#name "(" #F "[" FMT "])\n",P,Q)
#define DBGM2(name,a1,a2)					flat_dbg(#name "(" #a1 "," #a2 ")\n")
#define DBGTF(name,T,F,FMT,...)				flat_dbg(#name "(" #T "," #F "[" FMT "])\n", ##__VA_ARGS__)
#define DBGTNF(name,T,N,F,FMT,...)			flat_dbg(#name "(" #T "," #N "," #F "[" FMT "])\n", ##__VA_ARGS__)
#define DBGTFMF(name,T,F,FMT,P,PF,FF)		flat_dbg(#name "(" #T "," #F "[" FMT "]," #PF "," #FF ")\n",P)
#define DBGTFOMF(name,T,F,FMT,P,Q,PF,FF) 	flat_dbg(#name "(" #T "," #F "[" FMT "]," #PF "," #FF ")\n",P,Q)
#define DBGTNFOMF(name,T,N,F,FMT,P,Q,PF,FF) flat_dbg(#name "(" #T "," #N "," #F "[" FMT "]," #PF "," #FF ")\n",P,Q)
#define DBGTP(name,T,P)						flat_dbg(#name "(" #T "," #P "[%llx])\n", (uint64_t)P)
#define DBGTNP(name,T,N,P)					flat_dbg(#name "(" #T "," #N "," #P "[%llx])\n", (uint64_t)P)
#define DBGM3(name,a1,a2,a3)				flat_dbg(#name "(" #a1 "," #a2 "," #a3 ")\n")
#define DBGM4(name,a1,a2,a3,a4)				flat_dbg(#name "(" #a1 "," #a2 "," #a3 "," #a4 ")\n")
#define DBGM5(name,a1,a2,a3,a4,a5)			flat_dbg(#name "(" #a1 "," #a2 "," #a3 "," #a4 "," #a5 ")\n")
#define DBGM6(name,a1,a2,a3,a4,a5, a6)		flat_dbg(#name "(" #a1 "," #a2 "," #a3 "," #a4 "," #a5 "," #a6 ")\n")

/* Memory allocation */

static inline void *kflat_zalloc(struct kflat* kflat, size_t size, size_t n) {
#if LINEAR_MEMORY_ALLOCATOR > 0
	size_t alloc_size = ALIGN(size*n,__alignof__(unsigned long long));
	void* m = 0;
	if (unlikely(kflat->mptrindex+alloc_size>kflat->msize)) {
		static int diag_issued;
		if (!diag_issued) {
			flat_errs("Maximum capacity of kflat linear memory allocator (%zu) has been reached at %zu\n",
					kflat->msize,kflat->mptrindex);
			diag_issued = 1;
		}
		return 0;
	}
	m = (unsigned char*)kflat->mpool+kflat->mptrindex;
	kflat->mptrindex+=alloc_size;
	return m;
#else
	return kvzalloc(size*n,GFP_KERNEL);
#endif
}

static inline void kflat_free(const void* p) {
#if LINEAR_MEMORY_ALLOCATOR == 0
	kvfree(p);
#endif
}

static inline void *kflat_bqueue_zalloc(struct kflat* kflat, size_t size, size_t n) {
#if LINEAR_MEMORY_ALLOCATOR>0
	size_t alloc_size = ALIGN(size*n,__alignof__(unsigned long long));
	void* m = 0;
	if (unlikely(kflat->bqueue_mptrindex+alloc_size>kflat->bqueue_msize)) {
		static int diag_issued;
		if (!diag_issued) {
			flat_errs("Maximum capacity of kflat bqueue linear memory allocator (%zu) has been reached at %zu\n",
					kflat->bqueue_msize,kflat->bqueue_mptrindex);
			diag_issued = 1;
		}
		return 0;
	}
	m = (unsigned char*)kflat->bqueue_mpool+kflat->bqueue_mptrindex;
	kflat->bqueue_mptrindex+=alloc_size;
	return m;
#else
	return kvzalloc(size*n,GFP_KERNEL);
#endif
}

static inline struct flatten_pointer* make_flatten_pointer(struct kflat* kflat, struct flat_node* node, size_t offset) {
	struct flatten_pointer* v = kflat_zalloc(kflat,sizeof(struct flatten_pointer),1);
	if (v==0) return 0;
	v->node = node;
	v->offset = offset;
	return v;
}

static inline void destroy_flatten_pointer(struct flatten_pointer* fp) {
	kflat_free(fp->node->storage);
	kflat_free(fp->node);
	kflat_free(fp);
}

static inline size_t strmemlen(const char* s) {
	size_t str_size;
	size_t avail_size = kdump_test_address((void*) s, INT_MAX);
	if(avail_size == 0)
		return 0;

	str_size = strnlen(s, avail_size);
	if(str_size >= avail_size)
		// Missing null termiantor
		return str_size;

	return str_size + 1;
}

#define FLATTEN_MAGIC 0x464c415454454e00ULL

#define FLATTEN_WRITE_ONCE(addr,wsize,wcounter_p)	do {	\
	if ((*(wcounter_p)+wsize)>kflat->size) {	\
		kflat->errno = ENOMEM;		\
		return -1;			\
	}					\
	memcpy(kflat->area+(*(wcounter_p)),addr,wsize);	\
	*wcounter_p+=wsize;			\
} while(0);


#define ATTR(f)	((_ptr)->f)
#define OFFATTR(T,_off)	(*((T*)((unsigned char*)(_ptr)+_off)))
#define OFFATTRN(T,_off,_shift) (({	\
	void* p=*((T*)((unsigned char*)(_ptr)+_off));	\
	void* q = 0;	\
	if (p) q = p+_shift;	\
	q;	\
}))
#define OFFADDR(T,_off)	((T*)((unsigned char*)(_ptr)+_off))

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

#define ADDR_VALID(PTR)				(kdump_test_address((void*) PTR, 1))
#define ADDR_RANGE_VALID(PTR, SIZE) (_addr_range_valid((void*) PTR, SIZE))
#define TEXT_ADDR_VALID(PTR)		ADDR_VALID(PTR)		// TODO: Consider checking +x permission

#define STRUCT_ALIGN(n)		do { _alignment=n; } while(0)


/*************************************
 * FUNCTION_FLATTEN macros for ARRAYS
 *************************************/
#define FUNCTION_DEFINE_FLATTEN_GENERIC_COMPLEX(FUNC_NAME, TARGET_FUNC, FULL_TYPE, FLSIZE)	\
struct flatten_pointer* FUNC_NAME(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q) {    \
	size_t _i;			\
	void* _fp_first = NULL;		\
	const FULL_TYPE* _ptr = (const FULL_TYPE*) ptr;			\
	DBGS("%s(%lx,%zu)\n", __func__, (uintptr_t)_ptr, n);		\
	for (_i = 0; _i < n; ++_i) {					\
		void* _fp = (void*)TARGET_FUNC(kflat, (FULL_TYPE*)((u8*)_ptr + _i * FLSIZE), __q);	\
		if (_fp == NULL) {			\
			kflat_free(_fp_first);		\
			_fp_first = NULL;		\
			break;				\
		}					\
		if (_fp_first == NULL) _fp_first = _fp;	\
		else kflat_free(_fp);			\
	}						\
	if (kflat->errno) 				\
		return NULL;				\
	return _fp_first;				\
}


#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY(FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_COMPLEX(flatten_struct_array_##FLTYPE, flatten_struct_##FLTYPE, struct FLTYPE, sizeof(struct FLTYPE))

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);


#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_COMPLEX(flatten_struct_type_array_##FLTYPE, flatten_struct_type_##FLTYPE, FLTYPE, sizeof(FLTYPE))

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_array_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);


#define FUNCTION_DEFINE_FLATTEN_UNION_ARRAY(FLTYPE) \
	FUNCTION_DEFINE_FLATTEN_GENERIC_COMPLEX(flatten_union_array_##FLTYPE, flatten_union_##FLTYPE, union FLTYPE, sizeof(union FLTYPE))

#define FUNCTION_DECLARE_FLATTEN_UNION_ARRAY(FLTYPE) \
	extern struct flatten_pointer* flatten_union_array_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);


#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_COMPLEX(flatten_struct_array_##FLTYPE, flatten_struct_##FLTYPE, struct FLTYPE, FLSIZE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);


#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_COMPLEX(flatten_struct_type_array_##FLTYPE, flatten_struct_type_##FLTYPE, FLTYPE, FLSIZE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	extern struct flatten_pointer* flatten_struct_type_array_##FLTYPE(struct kflat* kflat, const void* _ptr, size_t n, struct bqueue* __q);


#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE) \
	FUNCTION_DEFINE_FLATTEN_GENERIC_COMPLEX(flatten_struct_array_##FLTYPE##_##TAG, flatten_struct_##FLTYPE##_##TAG, struct FLTYPE, FLSIZE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE) \
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE##_##TAG(struct kflat* kflat, const void* _ptr, size_t n, struct bqueue* __q);


#define FUNCTION_DEFINE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE) \
	FUNCTION_DEFINE_FLATTEN_GENERIC_COMPLEX(flatten_union_array_##FLTYPE, flatten_union_##FLTYPE, union FLTYPE, FLSIZE)

#define FUNCTION_DECLARE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE) \
	extern struct flatten_pointer* flatten_union_array_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);


/*************************************
 * FUNCTION_FLATTEN macros for types
 *************************************/
#define FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(FUNC_NAME, FULL_TYPE, FLSIZE, ...)  \
			\
struct flatten_pointer* FUNC_NAME(struct kflat* kflat, const void* ptr, struct bqueue* __q) {    \
            \
	struct flat_node *__node;		\
	typedef FULL_TYPE _container_type; \
	size_t _alignment = 0;  \
	struct flatten_pointer* r = 0;	\
	size_t _node_offset;	\
	const FULL_TYPE* _ptr = (const FULL_TYPE*) ptr;	\
        \
	DBGS("%s(%lx): [%zu]\n", __func__, (uintptr_t)_ptr, FLSIZE);	\
	__node = flatten_acquire_node_for_ptr(KFLAT_ACCESSOR, (void*) ptr, FLSIZE);	\
	\
	__VA_ARGS__ \
	if (kflat->errno) {   \
		DBGS("%s(%lx): %d\n", __func__, (uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(void*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("%s(%lx): EFAULT (__node==0)\n", __func__, (uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
	r = make_flatten_pointer(kflat,__node,_node_offset);	\
	if (!r) {	\
		kflat->errno = ENOMEM;	\
		DBGS("%s(%lx): ENOMEM\n", __func__, (uintptr_t)_ptr);	\
		return 0;	\
	}			\
	return r;		\
}


#define FUNCTION_DEFINE_FLATTEN_STRUCT(FLTYPE,...)  	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_##FLTYPE, struct FLTYPE, sizeof(struct FLTYPE), __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_##FLTYPE(struct kflat* kflat, const void*, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY(FLTYPE)


#define FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(FLTYPE,FLSIZE,...)	\
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_##FLTYPE, struct FLTYPE, FLSIZE, __VA_ARGS__) \
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)


#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(FLTYPE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_type_##FLTYPE, FLTYPE, sizeof(FLTYPE), __VA_ARGS__) \
	FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_##FLTYPE(struct kflat* kflat, const void*, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)


#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(FLTYPE,FLSIZE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_type_##FLTYPE, FLTYPE, FLSIZE, __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)


#define FUNCTION_DEFINE_FLATTEN_UNION(FLTYPE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_union_##FLTYPE, union FLTYPE, sizeof(union FLTYPE), __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY(FLTYPE)		// xxx TODO: are you sure?

#define FUNCTION_DECLARE_FLATTEN_UNION(FLTYPE) \
	extern struct flatten_pointer* flatten_union_##FLTYPE(struct kflat* kflat, const void*, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_UNION_ARRAY(FLTYPE)


#define FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_struct_##FLTYPE##_##TAG, struct FLTYPE, FLSIZE, __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE)


#define FUNCTION_DEFINE_FLATTEN_UNION_SELF_CONTAINED(FLTYPE,FLSIZE,...)  \
	FUNCTION_DEFINE_FLATTEN_GENERIC_BASE(flatten_union_##FLTYPE, union FLTYPE, FLSIZE, __VA_ARGS__)	\
	FUNCTION_DEFINE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)


/*******************************
 * FLATTEN macros
 *******************************/
#define FLATTEN_GENERIC(p, EL_SIZE, COUNT, FUNC)   \
	flatten_generic(KFLAT_ACCESSOR, __q, __fptr, p, EL_SIZE, COUNT, FUNC)

#define FLATTEN_STRUCT_ARRAY(T,p,n)	\
	DBGM3(FLATTEN_STRUCT_ARRAY,T,p,n);	\
	FLATTEN_GENERIC(p, sizeof(struct T), n, flatten_struct_array_##T)

#define FLATTEN_STRUCT(T,p)	\
	FLATTEN_STRUCT_ARRAY(T,p,1)

#define FLATTEN_STRUCT_ARRAY_SPECIALIZE(TAG,T,p,n)	\
	DBGM3(FLATTEN_STRUCT_ARRAY_SPECIALIZE,T,p,n);	\
	FLATTEN_GENERIC(p, sizeof(struct T), n, flatten_struct_array_##T##_##TAG)

#define FLATTEN_STRUCT_TYPE_ARRAY(T,p,n)	\
	DBGM3(FLATTEN_STRUCT_TYPE_ARRAY,T,p,n);	\
	FLATTEN_GENERIC(p, sizeof(T), n, flatten_struct_type_array_##T)

#define FLATTEN_STRUCT_TYPE(T,p)	\
	FLATTEN_STRUCT_TYPE_ARRAY(T,p,1)

#define FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T,N,p,n)	\
	DBGM4(FLATTEN_STRUCT_ARRAY_SELF_CONTAINED,T,N,p,n);	\
	FLATTEN_GENERIC(p, N, n, flatten_struct_array_##T)

#define FLATTEN_STRUCT_SELF_CONTAINED(T,N,p)	\
	FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T,N,p,1)

#define FLATTEN_UNION_ARRAY_SELF_CONTAINED(T,N,p,n)	\
	DBGM4(FLATTEN_UNION_ARRAY_SELF_CONTAINED,T,N,p,n);	\
	FLATTEN_GENERIC(p, N, n, flatten_union_array_##T)

#define FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,N,p,n)	\
	DBGM4(FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED,T,N,p,n);	\
	FLATTEN_GENERIC(p, N, n, flatten_struct_type_array_##T)

#define FLATTEN_STRUCT_TYPE_SELF_CONTAINED(T,N,p)	\
	FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,N,p,1)


/*******************************
 * AGGREGATE macros
 *******************************/
/* AGGREGATE_*_STORAGE */
#define AGGREGATE_FLATTEN_GENERIC_STORAGE(T,p,TARGET,CUSTOM_VAL)		\
	do {	\
		DBGTF(AGGREGATE_FLATTEN_GENERIC_STORAGE,T,p,"%lx",(unsigned long)p);	\
    	if (!KFLAT_ACCESSOR->errno) {	\
    		struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)p);	\
    		if (!__inode) {	\
    			int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
    			if (!err) {	\
    				struct flatten_job __job;   \
					__job.node = 0;    \
					__job.offset = 0; \
					__job.size = 1;	\
					__job.custom_val = (uintptr_t)CUSTOM_VAL;	\
					__job.ptr = (struct flatten_base*)p;    \
					__job.fun = TARGET;    \
					__job.fp = 0;   \
					__job.convert = 0;  \
					bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
    			}	\
				if (err && err != EEXIST) \
					KFLAT_ACCESSOR->errno = err;	\
    		}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_GENERIC_STORAGE: errno(%d)\n",KFLAT_ACCESSOR->errno);	\
    } while(0)

#define AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(FLTYPE, FLSIZE, OFF, TARGET)	\
	do {									\
		void* start, *end;					\
		size_t el_cnt, i;					\
											\
		bool rv = flatten_get_object((void*)_ptr, &start, &end);	\
		if(!rv)								\
			break;							\
											\
		el_cnt = (long)(end - start - OFF) / FLSIZE;	\
		if(el_cnt <= 0)						\
			break;							\
		for(i = 0; i < el_cnt; i++) {		\
			AGGREGATE_FLATTEN_GENERIC_STORAGE(FLTYPE, (((unsigned long)_ptr) + OFF  + i  * FLSIZE), TARGET);	\
		}									\
	} while(0)



#define AGGREGATE_FLATTEN_STRUCT_STORAGE(T,p)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(T, p, flatten_struct_array_##T)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE(T,p)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(T, p, flatten_struct_type_array_##T)

#define AGGREGATE_FLATTEN_UNION_STORAGE(T,p)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE(T, p, flatten_union_array_##T)


#define AGGREGATE_FLATTEN_STRUCT_FLEXIBLE(T, f) \
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(T, sizeof(struct T), offsetof(_container_type, f), flatten_struct_array_##T)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_FLEXIBLE(T, f)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(T, sizeof(T), offsetof(_container_type, f), flatten_struct_type_array_##T)

#define AGGREGATE_FLATTEN_UNION_FLEXIBLE(T, f)	\
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(T, sizeof(union T), offsetof(_container_type, f), flatten_union_array_##T)

#define AGGREGATE_FLATTEN_STRUCT_FLEXIBLE_SELF_CONTAINED(T, SIZE, OFF) \
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(T, SIZE, OFF, flatten_struct_array_##T)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_FLEXIBLE_SELF_CONTAINED(T, SIZE, OFF) \
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(T, SIZE, OFF, flatten_struct_type_array_##T)

#define AGGREGATE_FLATTEN_UNION_FLEXIBLE_SELF_CONTAINED(T, SIZE, OFF) \
	AGGREGATE_FLATTEN_GENERIC_STORAGE_FLEXIBLE(T, SIZE, OFF, flatten_union_array_##T)


/* AGGREGATE_* */
#define AGGREGATE_FLATTEN_GENERIC(FULL_TYPE,TARGET,N,f,_off,n,CUSTOM_VAL)	\
	do {	\
		DBGM5(AGGREGATE_FLATTEN_GENERIC,FULL_TYPE,N,f,_off,n);	\
		DBGS("FULL_TYPE [%lx:%zu -> %lx]\n",(uintptr_t)_ptr,(size_t)_off,(uintptr_t)OFFATTR(void*,_off));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), (n) * (N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(void*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			} else {	\
				int err;	\
				struct flatten_pointer* flat_ptr = flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(void*,_off),(n)*N);	\
				if(flat_ptr == NULL) {	\
					DBGS("AGGREGATE_FLATTEN_GENERIC:flatten_plain_type(): NULL");	\
					KFLAT_ACCESSOR->errno = EFAULT;	\
					break;	\
				}	\
				err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off, flat_ptr);	\
				if (err && err != EEXIST && err != EAGAIN) {	\
					DBGS("AGGREGATE_FLATTEN_GENERIC:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || err == EAGAIN) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						err = 0;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)OFFATTR(void*,_off)+_i*N),(uint64_t)((void*)OFFATTR(void*,_off)+(_i+1)*N-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)OFFATTR(void*,_off)+_i*N));	\
							if (!__struct_inode) {	\
								struct flatten_job __job;   \
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)OFFATTR(void*,_off)+_i*N));	\
								if (err) break;	\
								__job.node = 0;    \
								__job.offset = 0; \
								__job.size = 1;	\
								__job.custom_val = (uintptr_t)CUSTOM_VAL;	\
								__job.ptr = (struct flatten_base*)((void*)OFFATTR(void*,_off)+_i*N);    \
								__job.fun = TARGET;    \
								__job.fp = 0;   \
								__job.convert = 0;  \
								err = bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
								if (err) break;	\
							}	\
						}	\
						if ((err) && (err!=EEXIST)) {	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_GENERIC: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T,N,f,_off,n) \
	AGGREGATE_FLATTEN_GENERIC(struct T, flatten_struct_array_##T, N, f, _off, n)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,N,f,_off,n)	\
	AGGREGATE_FLATTEN_GENERIC(T, flatten_struct_type_array_##T, N, f, _off, n)

#define AGGREGATE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(T,N,f,_off,n)	\
	AGGREGATE_FLATTEN_GENERIC(union T, flatten_union_array_##T, N, f, _off, n)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY(T,f,n)	\
	DBGM3(AGGREGATE_FLATTEN_STRUCT_ARRAY,T,f,n); \
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T, sizeof(struct T), f, offsetof(_container_type, f), n)

#define AGGREGATE_FLATTEN_STRUCT(T,f)				\
	AGGREGATE_FLATTEN_STRUCT_ARRAY(T,f,1)

#define AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(T,N,f,_off) \
	AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T,N,f,_off,1)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(T,N,f,_off) \
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,N,f,_off,1)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY(T, f, n) \
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,sizeof(T),f,offsetof(_container_type, f), n)

#define AGGREGATE_FLATTEN_STRUCT_TYPE(T,f)	\
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY(T,f,1)



/* AGGREGATE_*_MIXED_POINTER */
#define AGGREGATE_FLATTEN_GENERIC_MIXED_POINTER(FULL_TYPE, TARGET, N, f, _off, pre_f, post_f)	\
	do {    \
		const FULL_TYPE* _fp;	\
		DBGTNFOMF(AGGREGATE_FLATTEN_GENERIC_MIXED_POINTER,FULL_TYPE,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off,pf,ff);  \
		_fp = pre_f((const FULL_TYPE*)OFFATTR(void*,_off)); \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,N))) {  \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(void*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)_fp);	\
				struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)_fp,\
						(uintptr_t)_fp+N-1);    \
				if ((!__inode)||(__struct_node==0)) {	\
					int err = 0;	\
					if (!__inode) {	\
						err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)_fp);	\
					}	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_GENERIC_MIXED_POINTER:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						struct flatten_job __job;   \
						int err;	\
						__job.node = __node;    \
						__job.offset = (uint64_t)_ptr-__node->start+_off; \
						__job.size = 1;	\
						__job.ptr = (struct flatten_base*)OFFATTR(void*, _off);    \
						__job.fun = TARGET;    \
						__job.fp = (const struct flatten_base*)_fp; \
						__job.convert = (flatten_struct_mixed_convert_t)&post_f; \
						err = bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
						if (err) {	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)_fp-__struct_node->start));	\
					if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("AGGREGATE_FLATTEN_GENERIC_MIXED_POINTER:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_GENERIC_MIXED_POINTER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)_fp);	\
	} while(0)

/* We would probably want the following versions at some point in time as well:
 * AGGREGATE_FLATTEN_STRUCT_STORAGE_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_STORAGE_MIXED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_MIXED_POINTER_ARRAY
 */



#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER(T,f,pre_f,post_f)	\
	AGGREGATE_FLATTEN_GENERIC_MIXED_POINTER(struct T, flatten_struct_array_##T, sizeof(struct T), f, offsetof(_container_type, f), pre_f, post_f)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER(T,f,pre_f,post_f)	\
	AGGREGATE_FLATTEN_GENERIC_MIXED_POINTER(T, flatten_struct_type_array_##T, sizeof(T), f, offsetof(_container_type, f), pre_f, post_f)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_SELF_CONTAINED(T,N,f,_off,pre_f,post_f)	\
	AGGREGATE_FLATTEN_GENERIC_MIXED_POINTER(T, flatten_struct_type_array_##T, N, f, _off, pre_f, post_f)

#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_SELF_CONTAINED(T,N,f,_off,pre_f,post_f) \
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED(T,N,f,_off,pre_f,post_f,1)	/* xxx TODO: Check this? */


#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED(T,N,f,_off,pre_f,post_f,n)	\
	do {	\
		const struct T* _fp;	\
		DBGTNFOMF(AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off,pf,ff);  \
		_fp = pre_f((const T*)OFFATTR(void*,_off)); \
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,(n)*(N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err;	\
				struct flatten_pointer* flatten_ptr = flatten_plain_type(KFLAT_ACCESSOR,_fp,(n)*N);	\
				if(flatten_ptr == NULL) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED:flatten_plain_type - NULL\n");	\
					KFLAT_ACCESSOR->errno = EFAULT; \
					break;	\
				}	\
				err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						post_f(flatten_ptr,(const T*)OFFATTR(void*,_off)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN)) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						err = 0;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)_fp+_i*N),(uint64_t)((void*)_fp+(_i+1)*N-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)_fp+_i*N));	\
							if (!__struct_inode) {	\
								struct flatten_job __job;   \
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)_fp+_i*N));	\
								if (err) break;	\
								__job.node = 0;    \
								__job.offset = 0; \
								__job.size = 1;	\
								__job.ptr = (struct flatten_base*)((void*)_fp+_i*N);    \
								__job.fun = &flatten_struct_array_##T;    \
								__job.fp = 0;   \
								__job.convert = 0;  \
								err = bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
								if (err) break;	\
							}	\
						}	\
						if ((err) && (err!=EEXIST)) {	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)


/* AGGREGATE_SHIFTED */
#define AGGREGATE_FLATTEN_GENERIC_SHIFTED(FULL_TYPE, TARGET, N,f,_off,n,_shift)	\
	do {	\
		DBGM6(AGGREGATE_FLATTEN_GENERIC_SHIFTED,FULL_TYPE,N,f,_off,n,_shift);	\
		DBGS("AGGREGATE_FLATTEN_GENERIC_SHIFTED [%lx:%zu -> %lx]\n",(uintptr_t)_ptr,(size_t)_off,(uintptr_t)OFFATTRN(void*,_off,_shift));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTRN(void*,_off,_shift), (n) * (N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(void*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err;	\
				struct flat_node* __ptr_node;	\
				struct flatten_pointer* __shifted = flatten_plain_type(KFLAT_ACCESSOR,OFFATTRN(void*,_off,_shift),(n)*N);	\
				if(__shifted == NULL) {	\
					DBGS("AGGREGATE_FLATTEN_GENERIC_SHIFTED:flatten_plain_type - NULL\n");	\
					KFLAT_ACCESSOR->errno = EFAULT; \
					break;	\
				}	\
				__ptr_node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uintptr_t)OFFATTR(void*,_off),	\
						(uintptr_t)OFFATTR(void*,_off)+1);	\
				__shifted->node = __ptr_node;	\
				__shifted->offset = (uintptr_t)OFFATTR(void*,_off) - __ptr_node->start;	\
				err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,__shifted);	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_GENERIC_SHIFTED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN)) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						err = 0;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)OFFATTRN(void*,_off,_shift)+_i*N),(uint64_t)((void*)OFFATTRN(void*,_off,_shift)+(_i+1)*N-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)OFFATTRN(void*,_off,_shift)+_i*N));	\
							if (!__struct_inode) {	\
								struct flatten_job __job;   \
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)OFFATTRN(void*,_off,_shift)+_i*N));	\
								if (err) break;	\
								__job.node = 0;    \
								__job.offset = 0; \
								__job.size = 1;	\
								__job.ptr = (struct flatten_base*)((void*)OFFATTRN(void*,_off,_shift)+_i*N);    \
								__job.fun = TARGET;    \
								__job.fp = 0;   \
								__job.convert = 0;  \
								err = bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
								if (err) break;	\
							}	\
						}	\
						if ((err) && (err!=EEXIST)) {	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_GENERIC_SHIFTED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTRN(void*,_off,_shift));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED_SHIFTED(T,N,f,_off,n,_shift)	\
	AGGREGATE_FLATTEN_GENERIC_SHIFTED(struct T, flatten_struct_array_##T, N,f,_off,n,_shift)

#define AGGREGATE_FLATTEN_UNION_ARRAY_SELF_CONTAINED_SHIFTED(T,N,f,_off,n,_shift)	\
	AGGREGATE_FLATTEN_GENERIC_SHIFTED(union T, flatten_union_array_##T, N,f,_off,n,_shift)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED_SHIFTED(T,N,f,_off,n,_shift)	\
	AGGREGATE_FLATTEN_GENERIC_SHIFTED(T, flatten_struct_type_array_##T, N,f,_off,n,_shift)

#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED(T,N,f,_off,pre_f,post_f,n,_shift)	\
	do {	\
		void* _p = pre_f((const struct T*)OFFATTR(void*,_off));	\
		const struct T* _fp = 0;	\
		if (_p) _fp = _p+_shift;	\
		DBGTNFOMF(AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED,T,N,f,"%lx:%zu",_fp,(size_t)_off,pf,ff);  \
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,(n)*(N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err;	\
				struct flat_node* __ptr_node;	\
				struct flatten_pointer* __shifted = flatten_plain_type(KFLAT_ACCESSOR,_fp,(n)*N);	\
				if(__shifted == NULL) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED:flatten_plain_type - NULL\n");	\
					KFLAT_ACCESSOR->errno = EFAULT; \
					break;	\
				}	\
				__ptr_node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uintptr_t)_fp-_shift,(uintptr_t)_fp-_shift+1);	\
				__shifted->node = __ptr_node;	\
				__shifted->offset = (uintptr_t)_fp-_shift - __ptr_node->start;	\
				err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
					post_f(__shifted,(const struct T*)OFFATTR(void*,_off)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN)) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						err = 0;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)_fp+_i*N),(uint64_t)((void*)_fp+(_i+1)*N-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)_fp+_i*N));	\
							if (!__struct_inode) {	\
								struct flatten_job __job;   \
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)_fp+_i*N));	\
								if (err) break;	\
								__job.node = 0;    \
								__job.offset = 0; \
								__job.size = 1;	\
								__job.ptr = (struct flatten_base*)((void*)_fp+_i*N);    \
								__job.fun = &flatten_struct_array_##T;    \
								__job.fp = 0;   \
								__job.convert = 0;  \
								err = bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
								if (err) break;	\
							}	\
						}	\
						if ((err) && (err!=EEXIST)) {	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_SELF_CONTAINED_SHIFTED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)


/*******************************
 * AGGERGATE & FLATTEN macros for
 *  generic types
 *******************************/
#define FLATTEN_COMPOUND_TYPE_ARRAY(T,N,p,n)	\
	do {	\
		DBGM4(FLATTEN_COMPOUND_TYPE_ARRAY,T,N,p,n);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n)*N))) {   \
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_plain_type(KFLAT_ACCESSOR,(p),(n)*N));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_COMPOUND_TYPE_ARRAY: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_TYPE_ARRAY(T,p,n)  	FLATTEN_COMPOUND_TYPE_ARRAY(T, sizeof(T), p, n)
#define FLATTEN_TYPE(T,p)			FLATTEN_COMPOUND_TYPE_ARRAY(T, sizeof(T), p, 1)

#define FLATTEN_STRING(p)	\
	do {	\
		DBGM1(FLATTEN_STRING,p);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_VALID(p))) {   \
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_plain_type(KFLAT_ACCESSOR,(p),strmemlen(p)));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_STRING: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_FUNCTION_POINTER(p)	\
	do {	\
		DBGM1(FLATTEN_FUNCTION_POINTER,p);	\
		if ((!KFLAT_ACCESSOR->errno)&&(TEXT_ADDR_VALID(p))) {   \
			int err = fixup_set_insert_fptr_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,(unsigned long)p);	\
			if ((err) && (err!=EEXIST)) {	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_FUNCTION_POINTER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define AGGREGATE_FLATTEN_TYPE_ARRAY(T,f,n)	\
	do {  \
		DBGM3(AGGREGATE_FLATTEN_TYPE_ARRAY,T,f,n);	\
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f), (n) * sizeof(T)))) {   \
        	size_t _off = offsetof(_container_type,f);	\
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,ATTR(f),(n)*sizeof(T)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_TYPE_ARRAY: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
    } while(0)

#define AGGREGATE_FLATTEN_TYPE(T,f)	AGGREGATE_FLATTEN_TYPE_ARRAY(T, f, 1)

#define AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED(T,N,f,_off,n)	\
	do {  \
		DBGM5(AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED,T,N,f,_off,n);	\
		DBGS("AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED[%lx]\n",(uintptr_t)OFFATTR(void*,_off));	\
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), (n) * (N)))) {   \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(void*,_off),(n)*N));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
    } while(0)

#define AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(T,f,_off,n) \
	AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED(T,sizeof(T),f,_off,n)
#define AGGREGATE_FLATTEN_TYPE_SELF_CONTAINED(T,N,f,_off) \
	AGGREGATE_FLATTEN_COMPOUND_TYPE_ARRAY_SELF_CONTAINED(T,sizeof(T),f,_off,1)


#define AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(f,_off)	\
	do {  \
		DBGOF(AGGREGATE_FLATTEN_STRING_SELF_CONTAINED,f,"%lx:%zu",(unsigned long)OFFATTR(const char*,_off),(size_t)_off);	\
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_VALID(OFFATTR(void*,_off)))) {   \
			struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(char*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(const char*,_off),strmemlen(OFFATTR(const char*,_off))));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRING_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
    } while(0)

#define AGGREGATE_FLATTEN_STRING(f)	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(f, offsetof(_container_type,f))

#define AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(f,_off)	\
	do {	\
		DBGOF(AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off);	\
        if ((!KFLAT_ACCESSOR->errno)&&(TEXT_ADDR_VALID(OFFATTR(void*,_off)))) {   \
			struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(int (*)(void))-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_fptr_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						(unsigned long)OFFATTR(void*,_off));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while (0)

#define AGGREGATE_FLATTEN_FUNCTION_POINTER(f) AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(f, offsetof(_container_type,f))

/* TODO: Use ADDR_RANGE_VALID */
#define FOREACH_POINTER(PTRTYPE,v,p,s,...)	\
	do {	\
		DBGM4(FOREACH_POINTER,PTRTYPE,v,p,s);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_VALID(p))) {	\
			PTRTYPE const * _m = (PTRTYPE const *)(p);	\
			size_t _i, _sz = (s);	\
			for (_i=0; _i<_sz; ++_i) {	\
				struct flatten_pointer* __fptr = flatten_plain_type(KFLAT_ACCESSOR,_m+_i,sizeof(void*));	\
				if (__fptr) {	\
					PTRTYPE v = *(_m+_i);	\
					__VA_ARGS__;	\
					kflat_free(__fptr);	\
				} \
				else {	\
					KFLAT_ACCESSOR->errno = ENOMEM;	\
					break;	\
				}	\
			}	\
		}	\
		else DBGS("FOREACH_POINTER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FOR_POINTER(PTRTYPE, v, p, ...)	\
	FOREACH_POINTER(PTRTYPE, v, p, 1, __VA_ARGS__)


/*******************************
 * FLATTEN entry point
 *******************************/
#define FOR_EXTENDED_ROOT_POINTER(p,__name,__size,...)	\
	do {	\
		struct bqueue bq;	\
		struct bqueue* __q;	\
		int err = bqueue_init(KFLAT_ACCESSOR, &bq, DEFAULT_ITER_QUEUE_SIZE);	\
		if (err) {	\
			KFLAT_ACCESSOR->errno = err;	\
			break;	\
		}	\
		__q = &bq;	\
					\
		DBGM3(FOR_EXTENDED_ROOT_POINTER,p,__name,__size);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_VALID(p))) {	\
			struct flatten_pointer* __fptr = make_flatten_pointer(KFLAT_ACCESSOR,0,0);	\
			const void* __root_ptr __attribute__((unused)) = (const void*) p;       \
			flatten_set_option(KFLAT_ACCESSOR,KFLAT_OPTION_IN_PROGRESS);	\
			if (__fptr) {	\
				__VA_ARGS__;	\
				kflat_free(__fptr);	\
			}	\
			else {	\
				KFLAT_ACCESSOR->errno = ENOMEM;	\
			}	\
			flatten_clear_option(KFLAT_ACCESSOR,KFLAT_OPTION_IN_PROGRESS);	\
		}	\
		if (!KFLAT_ACCESSOR->errno) {	\
			if(__name != NULL)	{ \
				int err = root_addr_append_extended(KFLAT_ACCESSOR, (uintptr_t)(p), __name, __size );	\
				if ((err) && (err!=EEXIST))		\
					KFLAT_ACCESSOR->errno = err;	\
			} else {	\
				KFLAT_ACCESSOR->errno = root_addr_append(KFLAT_ACCESSOR, (uintptr_t)(p) );	\
			}	\
		}	\
			\
		flatten_run_iter_harness(KFLAT_ACCESSOR, &bq);	\
	} while(0)

#define FOR_ROOT_POINTER(p,...) FOR_EXTENDED_ROOT_POINTER(p, NULL, 0, ##__VA_ARGS__)


/* Try to detect the size of the heap object pointed to by '__ptr'
 * When successfully detected it returns the size of the object starting from '__ptr' to the end of the object
 * When detection fails returns the value passed in '__default_size'
 */
#define FLATTEN_DETECT_OBJECT_SIZE(__ptr,__default_size) \
		({			\
			void *__start, *__end;	\
			bool rv = flatten_get_object(__ptr, &__start, &__end);	\
			(rv)?(__end-__ptr+1):(__default_size);	\
		})

#define PTRNODE(PTRV)	(interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uintptr_t)(PTRV), (uintptr_t)(PTRV)))
#define KFLAT_ACCESSOR kflat


/* Include wrappers for obsolete macros to support older recipes
 */
#include "kflat_compatibility.h"

#endif /* _LINUX_KFLAT_H */

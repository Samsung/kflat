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

extern int flatten_base_global_address;

#define kflat_fmt(fmt) 			"kflat: " fmt
#define flat_errs(fmt,...) 		printk(KERN_ERR kflat_fmt(fmt), ##__VA_ARGS__);
#define flat_infos(fmt,...) 	printk(KERN_INFO kflat_fmt(fmt), ##__VA_ARGS__);

#define LINEAR_MEMORY_ALLOCATOR	1
#define KFLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE	(256ULL*1024*1024)

#define DEFAULT_ITER_QUEUE_SIZE (1024*1024*8)

#define TIME_NS	1
#define TIME_US	(1000*TIME_NS)
#define TIME_MS	(1000*TIME_US)
#define TIME_S	(1000*TIME_MS)
#define KFLAT_PING_TIME_NS	(TIME_S)

#define STR(s) #s

#define GLOBAL_ADDR_OFFSET(addr0,addr1)	\
	((((unsigned long)addr0>=(unsigned long)addr1)?(1):(-1))*(long)(	\
		((unsigned long)addr0>=(unsigned long)addr1)?	\
				((unsigned long)addr0-(unsigned long)addr1):((unsigned long)addr1-(unsigned long)addr0)))

static inline void *libflat_zalloc(size_t size, size_t n) {
	return kvzalloc(size*n,GFP_KERNEL);
}

static inline void libflat_free(const void* p) {
	kvfree(p);
}

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
	int 				triggered;
	int 				is_armed;
	uint64_t 			return_ip;
	struct kprobe* 		kprobe;
};

struct kflat_recipe {
	struct list_head 	list;
	struct module*      owner;
	char* 				symbol;
	void 				(*handler)(struct kflat*, struct probe_regs*);
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
};

int kflat_recipe_register(struct kflat_recipe* recipe);
int kflat_recipe_unregister(struct kflat_recipe* recipe);
struct kflat_recipe* kflat_recipe_get(char* name);
void kflat_recipe_put(struct kflat_recipe* recipe);

static inline void *kflat_zalloc(struct kflat* kflat, size_t size, size_t n) {
#if LINEAR_MEMORY_ALLOCATOR>0
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
#if LINEAR_MEMORY_ALLOCATOR>0
#else
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

static inline void kflat_bqueue_free(const void* p) {
}

static inline void bqueue_release_memory(struct kflat* kflat) {
	kflat->bqueue_mptrindex = 0;
}

struct flatten_base {};

typedef struct flatten_pointer* (*flatten_struct_t)(struct kflat* kflat, const void*, size_t n, struct bqueue*);
typedef struct flatten_pointer* (*flatten_struct_mixed_convert_t)(struct flatten_pointer*, const struct flatten_base*);

typedef struct flatten_pointer* (*flatten_struct_iter_f)(struct kflat* kflat, const void* _ptr, struct bqueue* __q);
typedef struct flatten_pointer* (*flatten_struct_f)(struct kflat* kflat, const void* _ptr);

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

typedef void (*flatten_interface_arg_f)(struct kflat* kflat, const void* __arg);

struct ifns_node {
	struct rb_node node;
	char* s;
	flatten_interface_arg_f f;
};

struct root_addr_set_node* root_addr_set_search(struct kflat* kflat, const char* name);
int root_addr_set_insert(struct kflat* kflat, const char* name, uintptr_t v);
int root_addr_set_delete(struct kflat* kflat, const char* name);
void root_addr_set_destroy(struct kflat* kflat);
size_t root_addr_set_count(struct kflat* kflat);

struct flatten_job {
    struct flat_node* node;
    size_t offset;
    size_t size;
    struct flatten_base* ptr;
    flatten_struct_t fun;
    /* Mixed pointer support */
    const struct flatten_base* fp;
    flatten_struct_mixed_convert_t convert;
};

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

int bqueue_init(struct kflat* kflat, struct bqueue* q, size_t block_size);
void bqueue_destroy(struct bqueue* q);
int bqueue_empty(struct bqueue* q);
size_t bqueue_size(struct bqueue* q);
int bqueue_push_back(struct kflat* kflat, struct bqueue* q, const void* m, size_t s);
int bqueue_pop_front(struct bqueue* q, void* m, size_t s);

#define DBGC(b,...)		do { if (b!=0)	__VA_ARGS__; } while(0)

enum flatten_option {
	KFLAT_OPTION_SILENT = 0x01,
	KFLAT_OPTION_IN_PROGRESS = 0x10,
};

void flatten_set_option(struct kflat* kflat, int option);
void flatten_clear_option(struct kflat* kflat, int option);

extern unsigned long (*kflat_lookup_kallsyms_name)(const char* name);
bool flatten_get_object(void* ptr, void** start, void** end);
void* flatten_global_address_by_name(const char* name);
void* flatten_global_address(const char* module, uint64_t offset);

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
	return strlen(s)+1;
}

static inline size_t ptrarrmemlen(const void* const* m) {
	size_t count=1;
	while(*m) {
		count++;
		m++;
	}
	return count;
}

#define FLATTEN_MAGIC 0x464c415454454e00ULL

#define FLATTEN_WRITE_ONCE(addr,wsize,wcounter_p)	do {	\
		if ((*(wcounter_p)+wsize)>kflat->size) {	\
			kflat->errno = ENOMEM;	\
			return -1;	\
		}	\
		memcpy(kflat->area+(*(wcounter_p)),addr,wsize);	\
		*wcounter_p+=wsize;	\
} while(0);

#define DBGS(M, ...)					do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(M, ##__VA_ARGS__); } while(0)
#define DBGM1(name,a1)					do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #a1 ")\n"); } while(0)
#define DBGF(name,F,FMT,P)				do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #F "[" FMT "])\n",P); } while(0)
#define DBGOF(name,F,FMT,P,Q)			do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #F "[" FMT "])\n",P,Q); } while(0)
#define DBGM2(name,a1,a2)				do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #a1 "," #a2 ")\n"); } while(0)
#define DBGTF(name,T,F,FMT,P)			do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #T "," #F "[" FMT "])\n",P); } while(0)
#define DBGTNF(name,T,N,F,FMT,P)		do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #T "," #N "," #F "[" FMT "])\n",P); } while(0)
#define DBGTFMF(name,T,F,FMT,P,PF,FF)	do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #T "," #F "[" FMT "]," #PF "," #FF ")\n",P); } while(0)
#define DBGTFOMF(name,T,F,FMT,P,Q,PF,FF) do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #T "," #F "[" FMT "]," #PF "," #FF ")\n",P,Q); } while(0)
#define DBGTNFOMF(name,T,N,F,FMT,P,Q,PF,FF) do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #T "," #N "," #F "[" FMT "]," #PF "," #FF ")\n",P,Q); } while(0)
#define DBGTP(name,T,P)					do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #T "," #P "[%llx])\n", (uint64_t)P); } while(0)
#define DBGTNP(name,T,N,P)				do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #T "," #N "," #P "[%llx])\n", (uint64_t)P); } while(0)
#define DBGM3(name,a1,a2,a3)			do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #a1 "," #a2 "," #a3 ")\n"); } while(0)
#define DBGM4(name,a1,a2,a3,a4)			do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #a1 "," #a2 "," #a3 "," #a4 ")\n"); } while(0)
#define DBGM5(name,a1,a2,a3,a4,a5)		do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #a1 "," #a2 "," #a3 "," #a4 "," #a5 ")\n"); } while(0)
#define DBGM6(name,a1,a2,a3,a4,a5, a6)	do { if (KFLAT_ACCESSOR->FLCTRL.debug_flag&1) kflat_dbg_printf(#name "(" #a1 "," #a2 "," #a3 "," #a4 "," #a5 "," #a6 ")\n"); } while(0)

#define ATTR(f)	((_ptr)->f)
#define OFFATTR(T,_off)	(*((T*)((unsigned char*)(_ptr)+_off)))
#define OFFATTRN(T,_off,_shift) (({	\
	void* p=*((T*)((unsigned char*)(_ptr)+_off));	\
	void* q = 0;	\
	if (p) q = p+_shift;	\
	q;	\
}))
#define OFFADDR(T,_off)	((T*)((unsigned char*)(_ptr)+_off))

#define ADDR_VALID(PTR)				(kdump_test_address((void*) PTR, 1))

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

#define ADDR_RANGE_VALID(PTR, SIZE) (_addr_range_valid((void*) PTR, SIZE))
// TODO: Consider checking +x permission
#define TEXT_ADDR_VALID(PTR)		ADDR_VALID(PTR)

#define STRUCT_ALIGN(n)		do { _alignment=n; } while(0)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY(FLTYPE)	\
struct flatten_pointer* flatten_struct_array_##FLTYPE(struct kflat* kflat, const struct FLTYPE* _ptr, size_t n) {	\
	size_t _i;	\
	void* _fp_first=0;	\
	DBGS("flatten_struct_" #FLTYPE "_array(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {	\
		void* _fp = (void*)flatten_struct_##FLTYPE(kflat,_ptr+_i);	\
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;	\
		else kflat_free(_fp);	\
	}	\
	if (kflat->errno) {	\
		return 0;	\
	}	\
    return _fp_first;	\
}

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE(struct kflat* kflat, const struct FLTYPE* _ptr, size_t n);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)	\
struct flatten_pointer* flatten_struct_type_array_##FLTYPE(struct kflat* kflat, const FLTYPE* _ptr, size_t n) {	\
    size_t _i;	\
	void* _fp_first=0;	\
	DBGS("flatten_struct_type_" #FLTYPE "_array(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {	\
		void* _fp = (void*)flatten_struct_type_##FLTYPE(kflat,_ptr+_i);	\
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;	\
		else kflat_free(_fp);	\
	}	\
	if (kflat->errno) {	\
		return 0;	\
	}	\
    return _fp_first;	\
}

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_array_##FLTYPE(struct kflat* kflat, const FLTYPE* _ptr, size_t n);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_ITER(FLTYPE) \
struct flatten_pointer* flatten_struct_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q) {    \
    size_t _i;  \
    void* _fp_first=0;  \
	const struct FLTYPE* _ptr = (const struct FLTYPE*) ptr;	\
    DBGS("flatten_struct_" #FLTYPE "_array_iter(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {    \
		void* _fp = (void*)flatten_struct_iter_##FLTYPE(kflat,_ptr+_i,__q);    \
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;  \
		else kflat_free(_fp); \
	}   \
	if (kflat->errno) {	\
		return 0;	\
	}	\
	else {	\
		return _fp_first;   \
	}	\
}

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER(FLTYPE) \
	extern struct flatten_pointer* flatten_struct_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);


#define FUNCTION_DEFINE_FLATTEN_UNION_ARRAY_ITER(FLTYPE) \
struct flatten_pointer* flatten_union_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q) {    \
    size_t _i;  \
    void* _fp_first=0;  \
	const union FLTYPE* _ptr = (const union FLTYPE*) ptr;	\
    DBGS("flatten_union_" #FLTYPE "_array_iter(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {    \
		void* _fp = (void*)flatten_union_iter_##FLTYPE(kflat,_ptr+_i,__q);    \
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;  \
		else kflat_free(_fp); \
	}   \
	if (kflat->errno) {	\
		return 0;	\
	}	\
	else {	\
		return _fp_first;   \
	}	\
}

#define FUNCTION_DECLARE_FLATTEN_UNION_ARRAY_ITER(FLTYPE) \
	extern struct flatten_pointer* flatten_union_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);


#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_ITER(FLTYPE)    \
struct flatten_pointer* flatten_struct_type_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q) {    \
	size_t _i;  \
	void* _fp_first=0;  \
	const FLTYPE* _ptr = (const FLTYPE*) ptr;	\
	DBGS("flatten_struct_type_" #FLTYPE "_array_iter(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {    \
		void* _fp = (void*)flatten_struct_type_iter_##FLTYPE(kflat,_ptr+_i,__q);    \
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;  \
		else kflat_free(_fp); \
	}   \
	if (kflat->errno) {	\
		return 0;	\
	}	\
	else {	\
		return _fp_first;   \
	}	\
}

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_ITER(FLTYPE)    \
	extern struct flatten_pointer* flatten_struct_type_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
struct flatten_pointer* flatten_struct_array_##FLTYPE(struct kflat* kflat, const struct FLTYPE* _ptr, size_t n) {	\
	size_t _i;	\
	void* _fp_first=0;	\
	DBGS("flatten_struct_" #FLTYPE "_array(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {	\
		void* _fp = (void*)flatten_struct_##FLTYPE(kflat,(struct FLTYPE*)((unsigned char*)_ptr+_i*FLSIZE));	\
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;	\
		else kflat_free(_fp);	\
	}	\
	if (kflat->errno) {	\
		return 0;	\
	}	\
    return _fp_first;	\
}

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	extern struct flatten_pointer* flatten_struct_array_##FLTYPE(struct kflat* kflat, const struct FLTYPE* _ptr, size_t n);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
struct flatten_pointer* flatten_struct_type_array_##FLTYPE(struct kflat* kflat, const FLTYPE* _ptr, size_t n) {	\
    size_t _i;	\
	void* _fp_first=0;	\
	DBGS("flatten_struct_type_" #FLTYPE "_array(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {	\
		void* _fp = (void*)flatten_struct_type_##FLTYPE(kflat,(FLTYPE*)((unsigned char*)_ptr+_i*FLSIZE));	\
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;	\
		else kflat_free(_fp);	\
	}	\
	if (kflat->errno) {	\
		return 0;	\
	}	\
    return _fp_first;	\
}

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)	\
	extern struct flatten_pointer* flatten_struct_type_array_##FLTYPE(struct kflat* kflat, const FLTYPE* _ptr, size_t n);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(FLTYPE,FLSIZE) \
struct flatten_pointer* flatten_struct_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q) {    \
    size_t _i;  \
    void* _fp_first=0;  \
	const struct FLTYPE* _ptr = (const struct FLTYPE*) ptr; \
    DBGS("flatten_struct_" #FLTYPE "_array_iter(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {    \
		void* _fp = (void*)flatten_struct_iter_##FLTYPE(kflat,(struct FLTYPE*)((unsigned char*)_ptr+_i*FLSIZE),__q);    \
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;  \
		else kflat_free(_fp); \
	}   \
	if (kflat->errno) {	\
		return 0;	\
	}	\
	else {	\
		return _fp_first;   \
	}	\
}

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(FLTYPE,FLSIZE) \
	extern struct flatten_pointer* flatten_struct_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE) \
struct flatten_pointer* flatten_struct_array_iter_##FLTYPE##_##TAG(struct kflat* kflat, const struct FLTYPE* _ptr, size_t n, struct bqueue* __q) {    \
    size_t _i;  \
    void* _fp_first=0;  \
    DBGS("flatten_struct_" #FLTYPE "_array_iter(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {    \
		void* _fp = (void*)flatten_struct_iter_##FLTYPE##_##TAG(kflat,(struct FLTYPE*)((unsigned char*)_ptr+_i*FLSIZE),__q);    \
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;  \
		else kflat_free(_fp); \
	}   \
	if (kflat->errno) {	\
		return 0;	\
	}	\
	else {	\
		return _fp_first;   \
	}	\
}

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE) \
extern struct flatten_pointer* flatten_struct_array_iter_##FLTYPE##_##TAG(struct kflat* kflat, const struct FLTYPE* _ptr, size_t n, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED(FLTYPE,FLSIZE) \
struct flatten_pointer* flatten_union_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q) {    \
    size_t _i;  \
    void* _fp_first=0;  \
	const union FLTYPE* _ptr = (const union FLTYPE*) ptr;	\
    DBGS("flatten_union_" #FLTYPE "_array_iter(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {    \
		void* _fp = (void*)flatten_union_iter_##FLTYPE(kflat,(union FLTYPE*)((unsigned char*)_ptr+_i*FLSIZE),__q);    \
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;  \
		else kflat_free(_fp); \
	}   \
	if (kflat->errno) {	\
		return 0;	\
	}	\
	else {	\
		return _fp_first;   \
	}	\
}

#define FUNCTION_DECLARE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED(FLTYPE,FLSIZE) \
	extern struct flatten_pointer* flatten_union_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(FLTYPE,FLSIZE)    \
struct flatten_pointer* flatten_struct_type_array_iter_##FLTYPE(struct kflat* kflat, const void* ptr, size_t n, struct bqueue* __q) {    \
	size_t _i;  \
	void* _fp_first=0;  \
	const FLTYPE* _ptr = (const FLTYPE*) ptr;	\
	DBGS("flatten_struct_type_" #FLTYPE "_array_iter(%lx,%zu)\n",(uintptr_t)_ptr,n);	\
	for (_i=0; _i<n; ++_i) {    \
		void* _fp = (void*)flatten_struct_type_iter_##FLTYPE(kflat,(FLTYPE*)((unsigned char*)_ptr+_i*FLSIZE),__q);    \
		if (!_fp) {	\
			if (_fp_first) {	\
				kflat_free(_fp_first);	\
			}	\
			break;	\
		}	\
		if (!_fp_first) _fp_first=_fp;  \
		else kflat_free(_fp); \
	}   \
	if (kflat->errno) {	\
		return 0;	\
	}	\
	else {	\
		return _fp_first;   \
	}	\
}

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(FLTYPE,FLSIZE)    \
	extern struct flatten_pointer* flatten_struct_type_array_iter_##FLTYPE(struct kflat* kflat, const void* _ptr, size_t n, struct bqueue* __q);

#define FUNCTION_DEFINE_FLATTEN_STRUCT(FLTYPE,...)	\
			\
struct flatten_pointer* flatten_struct_##FLTYPE(struct kflat* kflat, const struct FLTYPE* _ptr) {	\
			\
	typedef struct FLTYPE _container_type;	\
	size_t _alignment = 0;	\
	struct flatten_pointer* r = 0;	\
	size_t _node_offset;	\
			\
	struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(struct FLTYPE)-1);	\
	(_container_type*)_ptr;	\
	DBGS("flatten_struct_" #FLTYPE "(%lx): [%zu]\n",(uintptr_t)_ptr,sizeof(struct FLTYPE));	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_struct_" #FLTYPE "(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+sizeof(struct FLTYPE)-1);	\
		}	\
		if ((uintptr_t)_ptr+sizeof(struct FLTYPE)>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_struct_" #FLTYPE "(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+sizeof(struct FLTYPE)-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+sizeof(struct FLTYPE)-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
	else {	\
		struct blstream* storage;	\
		struct rb_node* rb;	\
		struct rb_node* prev;	\
		__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
		if (!__node) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->start = (uint64_t)_ptr;	\
		__node->last = (uint64_t)_ptr + sizeof(struct FLTYPE)-1;	\
		interval_tree_insert(__node, &kflat->FLCTRL.imap_root);	\
		rb = &__node->rb;	\
		prev = rb_prev(rb);	\
		if (prev) {	\
			storage = binary_stream_insert_back(kflat,_ptr,sizeof(struct FLTYPE),((struct flat_node*)prev)->storage);	\
		}	\
		else {	\
			struct rb_node* next = rb_next(rb);	\
			if (next) {	\
				storage = binary_stream_insert_front(kflat,_ptr,sizeof(struct FLTYPE),((struct flat_node*)next)->storage);	\
			}	\
			else {	\
				storage = binary_stream_append(kflat,_ptr,sizeof(struct FLTYPE));	\
			}	\
		}	\
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->storage = storage;	\
	}	\
		\
	__VA_ARGS__	\
	if (kflat->errno) {   \
		DBGS("flatten_struct_" #FLTYPE "(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(struct FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_struct_" #FLTYPE "(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_##FLTYPE(struct kflat* kflat, const struct FLTYPE*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(FLTYPE,FLSIZE,...)	\
			\
struct flatten_pointer* flatten_struct_##FLTYPE(struct kflat* kflat, const struct FLTYPE* _ptr) {	\
			\
	size_t _alignment = 0;	\
	struct flatten_pointer* r = 0;	\
	size_t _node_offset;	\
			\
	struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+FLSIZE-1);	\
	(void*)_ptr;	\
	DBGS("flatten_struct_" #FLTYPE "(%lx): [%zu]\n",(uintptr_t)_ptr,FLSIZE);	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_struct_" #FLTYPE "(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+FLSIZE-1);	\
		}	\
		if ((uintptr_t)_ptr+sizeof(struct FLTYPE)>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_struct_" #FLTYPE "(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+FLSIZE-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+FLSIZE-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
	else {	\
		struct blstream* storage;	\
		struct rb_node* rb;	\
		struct rb_node* prev;	\
		__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
		if (!__node) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->start = (uint64_t)_ptr;	\
		__node->last = (uint64_t)_ptr + FLSIZE-1;	\
		interval_tree_insert(__node, &kflat->FLCTRL.imap_root);	\
		rb = &__node->rb;	\
		prev = rb_prev(rb);	\
		if (prev) {	\
			storage = binary_stream_insert_back(kflat,_ptr,FLSIZE,((struct flat_node*)prev)->storage);	\
		}	\
		else {	\
			struct rb_node* next = rb_next(rb);	\
			if (next) {	\
				storage = binary_stream_insert_front(kflat,_ptr,FLSIZE,((struct flat_node*)next)->storage);	\
			}	\
			else {	\
				storage = binary_stream_append(kflat,_ptr,FLSIZE);	\
			}	\
		}	\
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->storage = storage;	\
	}	\
		\
	__VA_ARGS__	\
	if (kflat->errno) {   \
		DBGS("flatten_struct_" #FLTYPE "(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(struct FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_struct_" #FLTYPE "(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_struct_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(FLTYPE,...)	\
			\
struct flatten_pointer* flatten_struct_type_##FLTYPE(struct kflat* kflat, const FLTYPE* _ptr) {	\
			\
	typedef FLTYPE _container_type;	\
	size_t _alignment = 0;	\
	struct flatten_pointer* r = 0;	\
	size_t _node_offset;	\
			\
	struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(FLTYPE)-1);	\
	(_container_type*)_ptr;	\
	DBGS("flatten_struct_type_" #FLTYPE "(%lx): [%zu]\n",(uintptr_t)_ptr,sizeof(FLTYPE));	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_struct_type_" #FLTYPE "(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+sizeof(FLTYPE)-1);	\
		}	\
		if ((uintptr_t)_ptr+sizeof(FLTYPE)>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_struct_type_" #FLTYPE "(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+sizeof(FLTYPE)-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+sizeof(FLTYPE)-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
	else {	\
		struct blstream* storage;	\
		struct rb_node* rb;	\
		struct rb_node* prev;	\
		__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
		if (!__node) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->start = (uint64_t)_ptr;	\
		__node->last = (uint64_t)_ptr + sizeof(FLTYPE)-1;	\
		interval_tree_insert(__node, &kflat->FLCTRL.imap_root);	\
		rb = &__node->rb;	\
		prev = rb_prev(rb);	\
		if (prev) {	\
			storage = binary_stream_insert_back(kflat,_ptr,sizeof(FLTYPE),((struct flat_node*)prev)->storage);	\
		}	\
		else {	\
			struct rb_node* next = rb_next(rb);	\
			if (next) {	\
				storage = binary_stream_insert_front(kflat,_ptr,sizeof(FLTYPE),((struct flat_node*)next)->storage);	\
			}	\
			else {	\
				storage = binary_stream_append(kflat,_ptr,sizeof(FLTYPE));	\
			}	\
		}	\
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->storage = storage;	\
	}	\
		\
	__VA_ARGS__	\
	if (kflat->errno) {   \
		DBGS("flatten_struct_type_" #FLTYPE "(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_struct_type_" #FLTYPE "(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(FLTYPE)	\
	extern struct flatten_pointer* flatten_struct_type_##FLTYPE(struct kflat* kflat, const FLTYPE*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(FLTYPE,FLSIZE,...)	\
			\
struct flatten_pointer* flatten_struct_type_##FLTYPE(struct kflat* kflat, const FLTYPE* _ptr) {	\
			\
	size_t _alignment = 0;	\
	struct flatten_pointer* r = 0;	\
	size_t _node_offset;	\
			\
	struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+FLSIZE-1);	\
	(void*)_ptr;	\
	DBGS("flatten_struct_type_" #FLTYPE "(%lx): [%zu]\n",(uintptr_t)_ptr,FLSIZE);	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_struct_type_" #FLTYPE "(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+FLSIZE-1);	\
		}	\
		if ((uintptr_t)_ptr+FLSIZE>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_struct_type_" #FLTYPE "(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+FLSIZE-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+FLSIZE-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
	else {	\
		struct blstream* storage;	\
		struct rb_node* rb;	\
		struct rb_node* prev;	\
		__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
		if (!__node) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->start = (uint64_t)_ptr;	\
		__node->last = (uint64_t)_ptr + sizeof(FLTYPE)-1;	\
		interval_tree_insert(__node, &kflat->FLCTRL.imap_root);	\
		rb = &__node->rb;	\
		prev = rb_prev(rb);	\
		if (prev) {	\
			storage = binary_stream_insert_back(kflat,_ptr,FLSIZE,((struct flat_node*)prev)->storage);	\
		}	\
		else {	\
			struct rb_node* next = rb_next(rb);	\
			if (next) {	\
				storage = binary_stream_insert_front(kflat,_ptr,FLSIZE,((struct flat_node*)next)->storage);	\
			}	\
			else {	\
				storage = binary_stream_append(kflat,_ptr,FLSIZE);	\
			}	\
		}	\
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->storage = storage;	\
	}	\
		\
	__VA_ARGS__	\
	if (kflat->errno) {   \
		DBGS("flatten_struct_type_" #FLTYPE "(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_struct_type_" #FLTYPE "(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_struct_type_" #FLTYPE "(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(FLTYPE,FLSIZE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ITER(FLTYPE,...)  \
			\
struct flatten_pointer* flatten_struct_iter_##FLTYPE(struct kflat* kflat, const void* ptr, struct bqueue* __q) {    \
            \
    typedef struct FLTYPE _container_type;  \
    size_t _alignment = 0;  \
    struct flatten_pointer* r = 0;	\
    size_t _node_offset;	\
	const struct FLTYPE* _ptr = (const struct FLTYPE*) ptr;	\
            \
    struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(struct FLTYPE)-1);    \
    (_container_type*)_ptr;	\
    DBGS("flatten_struct_" #FLTYPE "_iter(%lx): [%zu]\n",(uintptr_t)_ptr,sizeof(struct FLTYPE));	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_struct_" #FLTYPE "_iter(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+sizeof(struct FLTYPE)-1);	\
		}	\
		if ((uintptr_t)_ptr+sizeof(struct FLTYPE)>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_struct_" #FLTYPE "_iter(%lx): EFAULT (prev(%llx)->storage==0)\n",(uintptr_t)_ptr, (uint64_t)prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+sizeof(struct FLTYPE)-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+sizeof(struct FLTYPE)-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
    else {  \
    	struct blstream* storage;   \
    	struct rb_node* rb;	\
    	struct rb_node* prev;	\
    	__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);   \
    	if (!__node) {	\
    		kflat->errno = ENOMEM;	\
    		DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->start = (uint64_t)_ptr; \
        __node->last = (uint64_t)_ptr + sizeof(struct FLTYPE)-1;    \
        interval_tree_insert(__node, &kflat->FLCTRL.imap_root);   \
        rb = &__node->rb;	\
        prev = rb_prev(rb); \
        if (prev) { \
            storage = binary_stream_insert_back(kflat,_ptr,sizeof(struct FLTYPE),((struct flat_node*)prev)->storage);    \
        }   \
        else {  \
            struct rb_node* next = rb_next(rb); \
            if (next) { \
                storage = binary_stream_insert_front(kflat,_ptr,sizeof(struct FLTYPE),((struct flat_node*)next)->storage);   \
            }   \
            else {  \
                storage = binary_stream_append(kflat,_ptr,sizeof(struct FLTYPE)); \
            }   \
        }   \
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->storage = storage;  \
    }   \
        \
    __VA_ARGS__ \
	if (kflat->errno) {   \
		DBGS("flatten_struct_" #FLTYPE "_iter(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(struct FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_struct_" #FLTYPE "_iter(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_ITER(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_ITER(FLTYPE) \
    extern struct flatten_pointer* flatten_struct_iter_##FLTYPE(struct kflat* kflat, const void*, struct bqueue*);	\
    FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_UNION_ITER(FLTYPE,...)  \
			\
struct flatten_pointer* flatten_union_iter_##FLTYPE(struct kflat* kflat, const void* ptr, struct bqueue* __q) {    \
            \
    typedef union FLTYPE _container_type;  \
    size_t _alignment = 0;  \
    struct flatten_pointer* r = 0;	\
    size_t _node_offset;	\
	const union FLTYPE* _ptr = (const union FLTYPE*) ptr; \
            \
    struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(union FLTYPE)-1);    \
    (_container_type*)_ptr;	\
    DBGS("flatten_union_" #FLTYPE "_iter(%lx): [%zu]\n",(uintptr_t)_ptr,sizeof(union FLTYPE));	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_union_" #FLTYPE "_iter(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+sizeof(union FLTYPE)-1);	\
		}	\
		if ((uintptr_t)_ptr+sizeof(union FLTYPE)>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_union_" #FLTYPE "_iter(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+sizeof(union FLTYPE)-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+sizeof(union FLTYPE)-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
    else {  \
    	struct blstream* storage;   \
    	struct rb_node* rb;	\
    	struct rb_node* prev;	\
    	__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);   \
    	if (!__node) {	\
    		kflat->errno = ENOMEM;	\
    		DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->start = (uint64_t)_ptr; \
        __node->last = (uint64_t)_ptr + sizeof(union FLTYPE)-1;    \
        interval_tree_insert(__node, &kflat->FLCTRL.imap_root);   \
        rb = &__node->rb;	\
        prev = rb_prev(rb); \
        if (prev) { \
            storage = binary_stream_insert_back(kflat,_ptr,sizeof(union FLTYPE),((struct flat_node*)prev)->storage);    \
        }   \
        else {  \
            struct rb_node* next = rb_next(rb); \
            if (next) { \
                storage = binary_stream_insert_front(kflat,_ptr,sizeof(union FLTYPE),((struct flat_node*)next)->storage);   \
            }   \
            else {  \
                storage = binary_stream_append(kflat,_ptr,sizeof(union FLTYPE)); \
            }   \
        }   \
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->storage = storage;  \
    }   \
        \
    __VA_ARGS__ \
	if (kflat->errno) {   \
		DBGS("flatten_union_" #FLTYPE "_iter(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(union FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_union_" #FLTYPE "_iter(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_ITER(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_UNION_ITER(FLTYPE) \
    extern struct flatten_pointer* flatten_union_iter_##FLTYPE(struct kflat* kflat, const void*, struct bqueue*);	\
    FUNCTION_DECLARE_FLATTEN_UNION_ARRAY_ITER(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(FLTYPE,FLSIZE,...)  \
			\
struct flatten_pointer* flatten_struct_iter_##FLTYPE(struct kflat* kflat, const void* ptr, struct bqueue* __q) {    \
            \
    size_t _alignment = 0;  \
    struct flatten_pointer* r = 0;	\
    size_t _node_offset;	\
	const struct FLTYPE* _ptr = (const struct FLTYPE*) ptr;	\
            \
    struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+FLSIZE-1);    \
    (void*)_ptr;	\
    DBGS("flatten_struct_" #FLTYPE "_iter(%lx): [%zu]\n",(uintptr_t)_ptr,FLSIZE);	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_struct_" #FLTYPE "_iter(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+FLSIZE-1);	\
		}	\
		if ((uintptr_t)_ptr+FLSIZE>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_struct_" #FLTYPE "_iter(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+FLSIZE-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+FLSIZE-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
    else {  \
    	struct blstream* storage;   \
    	struct rb_node* rb;	\
    	struct rb_node* prev;	\
    	__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);   \
    	if (!__node) {	\
    		kflat->errno = ENOMEM;	\
    		DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->start = (uint64_t)_ptr; \
        __node->last = (uint64_t)_ptr + FLSIZE-1;    \
        interval_tree_insert(__node, &kflat->FLCTRL.imap_root);   \
        rb = &__node->rb;	\
        prev = rb_prev(rb); \
        if (prev) { \
            storage = binary_stream_insert_back(kflat,_ptr,FLSIZE,((struct flat_node*)prev)->storage);    \
        }   \
        else {  \
            struct rb_node* next = rb_next(rb); \
            if (next) { \
                storage = binary_stream_insert_front(kflat,_ptr,FLSIZE,((struct flat_node*)next)->storage);   \
            }   \
            else {  \
                storage = binary_stream_append(kflat,_ptr,FLSIZE); \
            }   \
        }   \
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->storage = storage;  \
    }   \
        \
    __VA_ARGS__ \
	if (kflat->errno) {   \
		DBGS("flatten_struct_" #FLTYPE "_iter(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(struct FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_struct_" #FLTYPE "_iter(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(FLTYPE,FLSIZE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE,...)  \
			\
struct flatten_pointer* flatten_struct_iter_##FLTYPE##_##TAG(struct kflat* kflat, const struct FLTYPE* _ptr, struct bqueue* __q) {    \
            \
    size_t _alignment = 0;  \
    struct flatten_pointer* r = 0;	\
    size_t _node_offset;	\
            \
    struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+FLSIZE-1);    \
    (void*)_ptr;	\
    (void)interval_tree_remove;	\
    DBGS("flatten_struct_" #FLTYPE "_iter(%lx): [%zu]\n",(uintptr_t)_ptr,FLSIZE);	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_struct_" #FLTYPE "_iter(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+FLSIZE-1);	\
		}	\
		if ((uintptr_t)_ptr+FLSIZE>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_struct_" #FLTYPE "_iter(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+FLSIZE-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+FLSIZE-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
    else {  \
    	struct blstream* storage;   \
    	struct rb_node* rb;	\
    	struct rb_node* prev;	\
    	__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);   \
    	if (!__node) {	\
    		kflat->errno = ENOMEM;	\
    		DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->start = (uint64_t)_ptr; \
        __node->last = (uint64_t)_ptr + FLSIZE-1;    \
        interval_tree_insert(__node, &kflat->FLCTRL.imap_root);   \
        rb = &__node->rb;	\
        prev = rb_prev(rb); \
        if (prev) { \
            storage = binary_stream_insert_back(kflat,_ptr,FLSIZE,((struct flat_node*)prev)->storage);    \
        }   \
        else {  \
            struct rb_node* next = rb_next(rb); \
            if (next) { \
                storage = binary_stream_insert_front(kflat,_ptr,FLSIZE,((struct flat_node*)next)->storage);   \
            }   \
            else {  \
                storage = binary_stream_append(kflat,_ptr,FLSIZE); \
            }   \
        }   \
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->storage = storage;  \
    }   \
        \
    __VA_ARGS__ \
	if (kflat->errno) {   \
		DBGS("flatten_struct_" #FLTYPE "_iter(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(struct FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_struct_" #FLTYPE "_iter(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_struct_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SPECIALIZE(TAG,FLTYPE,FLSIZE)

#define FUNCTION_DEFINE_FLATTEN_UNION_ITER_SELF_CONTAINED(FLTYPE,FLSIZE,...)  \
			\
struct flatten_pointer* flatten_union_iter_##FLTYPE(struct kflat* kflat, const void* ptr, struct bqueue* __q) {    \
            \
    size_t _alignment = 0;  \
    struct flatten_pointer* r = 0;	\
    size_t _node_offset;	\
	const union FLTYPE* _ptr = (const union FLTYPE*) ptr;	\
            \
    struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+FLSIZE-1);    \
    (void*)_ptr;	\
    DBGS("flatten_union_" #FLTYPE "_iter(%lx): [%zu]\n",(uintptr_t)_ptr,FLSIZE);	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_union_" #FLTYPE "_iter(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+FLSIZE-1);	\
		}	\
		if ((uintptr_t)_ptr+FLSIZE>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_union_" #FLTYPE "_iter(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+FLSIZE-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+FLSIZE-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
    else {  \
    	struct blstream* storage;   \
    	struct rb_node* rb;	\
    	struct rb_node* prev;	\
    	__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);   \
    	if (!__node) {	\
    		kflat->errno = ENOMEM;	\
    		DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->start = (uint64_t)_ptr; \
        __node->last = (uint64_t)_ptr + FLSIZE-1;    \
        interval_tree_insert(__node, &kflat->FLCTRL.imap_root);   \
        rb = &__node->rb;	\
        prev = rb_prev(rb); \
        if (prev) { \
            storage = binary_stream_insert_back(kflat,_ptr,FLSIZE,((struct flat_node*)prev)->storage);    \
        }   \
        else {  \
            struct rb_node* next = rb_next(rb); \
            if (next) { \
                storage = binary_stream_insert_front(kflat,_ptr,FLSIZE,((struct flat_node*)next)->storage);   \
            }   \
            else {  \
                storage = binary_stream_append(kflat,_ptr,FLSIZE); \
            }   \
        }   \
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
        __node->storage = storage;  \
    }   \
        \
    __VA_ARGS__ \
	if (kflat->errno) {   \
		DBGS("flatten_union_" #FLTYPE "_iter(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(union FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_union_" #FLTYPE "_iter(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_union_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED(FLTYPE,FLSIZE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ITER(FLTYPE,...)  \
            \
struct flatten_pointer* flatten_struct_type_iter_##FLTYPE(struct kflat* kflat, const void* ptr, struct bqueue* __q) {    \
			\
	typedef FLTYPE _container_type;  \
	size_t _alignment = 0;  \
	struct flatten_pointer* r = 0;	\
	size_t _node_offset;	\
	const FLTYPE* _ptr = (const FLTYPE*) ptr; \
			\
	struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(FLTYPE)-1);    \
	(_container_type*)_ptr;	\
	DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): [%zu]\n",(uintptr_t)_ptr,sizeof(FLTYPE));	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+sizeof(FLTYPE)-1);	\
		}	\
		if ((uintptr_t)_ptr+sizeof(FLTYPE)>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+sizeof(FLTYPE)-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+sizeof(FLTYPE)-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
	else {  \
		struct blstream* storage;   \
		struct rb_node* rb;	\
		struct rb_node* prev;	\
		__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);   \
		if (!__node) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->start = (uint64_t)_ptr; \
		__node->last = (uint64_t)_ptr + sizeof(FLTYPE)-1;    \
		interval_tree_insert(__node, &kflat->FLCTRL.imap_root);   \
		rb = &__node->rb;	\
		prev = rb_prev(rb); \
		if (prev) { \
			storage = binary_stream_insert_back(kflat,_ptr,sizeof(FLTYPE),((struct flat_node*)prev)->storage);    \
		}   \
		else {  \
			struct rb_node* next = rb_next(rb); \
			if (next) { \
				storage = binary_stream_insert_front(kflat,_ptr,sizeof(FLTYPE),((struct flat_node*)next)->storage);   \
			}   \
			else {  \
				storage = binary_stream_append(kflat,_ptr,sizeof(FLTYPE)); \
			}   \
		}   \
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->storage = storage;  \
	}   \
		\
	__VA_ARGS__ \
	if (kflat->errno) {   \
		DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(struct FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_ITER(FLTYPE)

#define FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ITER(FLTYPE) \
	extern struct flatten_pointer* flatten_struct_type_iter_##FLTYPE(struct kflat* kflat, const void*, struct bqueue*);	\
	FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE_ARRAY_ITER(FLTYPE)

#define FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED(FLTYPE,FLSIZE,...)  \
            \
struct flatten_pointer* flatten_struct_type_iter_##FLTYPE(struct kflat* kflat, const void* ptr, struct bqueue* __q) {    \
			\
	size_t _alignment = 0;  \
	struct flatten_pointer* r = 0;	\
	size_t _node_offset;	\
	const FLTYPE* _ptr = (const FLTYPE*) ptr;	\
			\
	struct flat_node *__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+FLSIZE-1);    \
	(void*)_ptr;	\
	DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): [%zu]\n",(uintptr_t)_ptr,FLSIZE);	\
	if (__node) {	\
		uintptr_t p = (uintptr_t)_ptr;	\
    	struct flat_node *prev;	\
    	while(__node) {	\
			if (__node->start>p) {	\
				struct flat_node* nn;	\
				if (__node->storage==0) {	\
					kflat->errno = EFAULT;	\
					DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): EFAULT (__node(%lx)->storage==0)\n",(uintptr_t)_ptr,__node);	\
					return 0;	\
				}	\
				nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
				if (nn==0) {	\
					kflat->errno = ENOMEM;	\
					DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
					return 0;	\
				}	\
				nn->start = p;	\
				nn->last = __node->start-1;	\
				nn->storage = binary_stream_insert_front(kflat,(void*)p,__node->start-p,__node->storage);	\
				interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
			}	\
			p = __node->last+1;	\
			prev = __node;	\
			__node = interval_tree_iter_next(__node, (uintptr_t)_ptr, (uintptr_t)_ptr+FLSIZE-1);	\
		}	\
		if ((uintptr_t)_ptr+FLSIZE>p) {	\
			struct flat_node* nn;	\
			if (prev->storage==0) {	\
				kflat->errno = EFAULT;	\
				DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): EFAULT (prev(%lx)->storage==0)\n",(uintptr_t)_ptr,prev);	\
				return 0;	\
			}	\
			nn = kflat_zalloc(kflat,sizeof(struct flat_node),1);	\
			if (nn==0) {	\
				kflat->errno = ENOMEM;	\
				DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
				return 0;	\
			}	\
			nn->start = p;	\
			nn->last = (uintptr_t)_ptr+FLSIZE-1;	\
			nn->storage = binary_stream_insert_back(kflat,(void*)p,(uintptr_t)_ptr+FLSIZE-p,prev->storage);	\
			interval_tree_insert(nn, &kflat->FLCTRL.imap_root);	\
		}	\
	}	\
	else {  \
		struct blstream* storage;   \
		struct rb_node* rb;	\
		struct rb_node* prev;	\
		__node = kflat_zalloc(kflat,sizeof(struct flat_node),1);   \
		if (!__node) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->start = (uint64_t)_ptr; \
		__node->last = (uint64_t)_ptr + FLSIZE-1;    \
		interval_tree_insert(__node, &kflat->FLCTRL.imap_root);   \
		rb = &__node->rb;	\
		prev = rb_prev(rb); \
		if (prev) { \
			storage = binary_stream_insert_back(kflat,_ptr,FLSIZE,((struct flat_node*)prev)->storage);    \
		}   \
		else {  \
			struct rb_node* next = rb_next(rb); \
			if (next) { \
				storage = binary_stream_insert_front(kflat,_ptr,FLSIZE,((struct flat_node*)next)->storage);   \
			}   \
			else {  \
				storage = binary_stream_append(kflat,_ptr,FLSIZE); \
			}   \
		}   \
		if (!storage) {	\
			kflat->errno = ENOMEM;	\
			DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
			return 0;	\
		}	\
		__node->storage = storage;  \
	}   \
		\
	__VA_ARGS__ \
	if (kflat->errno) {   \
		DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): %d\n",(uintptr_t)_ptr,kflat->errno);	\
		return 0;	\
	}	\
	__node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uint64_t)_ptr, (uint64_t)_ptr+sizeof(struct FLTYPE*)-1);    \
	if (__node==0) {	\
		kflat->errno = EFAULT;	\
		DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): EFAULT (__node==0)\n",(uintptr_t)_ptr);	\
		return 0;	\
	}	\
	_node_offset = (uint64_t)_ptr-__node->start;	\
	__node->storage->alignment = _alignment;	\
	__node->storage->align_offset = _node_offset;	\
    r = make_flatten_pointer(kflat,__node,_node_offset);	\
    if (!r) {	\
    	kflat->errno = ENOMEM;	\
    	DBGS("flatten_struct_type_" #FLTYPE "_iter(%lx): ENOMEM\n",(uintptr_t)_ptr);	\
    	return 0;	\
    }	\
	return r;	\
}	\
\
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(FLTYPE,FLSIZE)

#define FLATTEN_STRUCT(T,p)	\
	do {	\
		DBGTP(FLATTEN_STRUCT,T,p);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, sizeof(struct T)))) {   \
			struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uintptr_t)p);	\
			if (!__inode) {	\
				int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
				if (err) {	\
					DBGS("FLATTEN_STRUCT:fixup_set_reserve_address(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_##T(KFLAT_ACCESSOR,(p)));	\
					if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
			else {	\
				struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)p,\
						(uintptr_t)p+sizeof(struct T)-1);    \
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,make_flatten_pointer(KFLAT_ACCESSOR,__node,(uintptr_t)p-__node->start));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("FLATTEN_STRUCT:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
		}	\
		else DBGS("FLATTEN_STRUCT: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_STRUCT_TYPE(T,p)	\
	do {	\
		DBGTP(FLATTEN_STRUCT_TYPE,T,p);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, sizeof(T)))) {   \
			struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uintptr_t)p);	\
			if (!__inode) {	\
				int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
				if (err) {	\
					DBGS("FLATTEN_STRUCT_TYPE:fixup_set_reserve_address(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_type_##T(KFLAT_ACCESSOR,(p)));	\
					if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_TYPE:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
			else {	\
				struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)p,\
						(uintptr_t)p+sizeof(T)-1);    \
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,make_flatten_pointer(KFLAT_ACCESSOR,__node,(uintptr_t)p-__node->start));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("FLATTEN_STRUCT_TYPE:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
		}	\
		else DBGS("FLATTEN_STRUCT_TYPE: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)


#define FLATTEN_STRUCT_ITER(T,p)	\
	do {    \
        DBGTP(FLATTEN_STRUCT_ITER,T,p);  \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, sizeof(struct T)))) {   \
			struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uintptr_t)p);	\
			if (!__inode) {	\
				int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
				if (err) {	\
					DBGS("FLATTEN_STRUCT_ITER:fixup_set_reserve_address(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_iter_##T(KFLAT_ACCESSOR,(p),__q));	\
					if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
			else {	\
				struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)p,\
						(uintptr_t)p+sizeof(struct T)-1);    \
				if (__node==0) {	\
					KFLAT_ACCESSOR->errno = EFAULT;	\
				}	\
				else {	\
					int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,make_flatten_pointer(KFLAT_ACCESSOR,__node,(uintptr_t)p-__node->start));	\
					if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("FLATTEN_STRUCT_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
    } while(0)



#define FLATTEN_STRUCT_TYPE_ITER(T,p)	\
	do {    \
        DBGTP(FLATTEN_STRUCT_TYPE_ITER,T,p);  \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, sizeof(T)))) {   \
			struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uintptr_t)p);	\
			if (!__inode) {	\
				int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
				if (err) {	\
					DBGS("FLATTEN_STRUCT_TYPE_ITER:fixup_set_reserve_address(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_type_iter_##T(KFLAT_ACCESSOR,(p),__q));	\
					if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_TYPE_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
			else {	\
				struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)p,\
						(uintptr_t)p+sizeof(T)-1);    \
				if (__node==0) {	\
					KFLAT_ACCESSOR->errno = EFAULT;	\
				}	\
				else {	\
					int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,make_flatten_pointer(KFLAT_ACCESSOR,__node,(uintptr_t)p-__node->start));	\
					if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_TYPE_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("FLATTEN_STRUCT_TYPE_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
    } while(0)

#define FLATTEN_STRUCT_SELF_CONTAINED(T,N,p)	\
	do {	\
		DBGTNP(FLATTEN_STRUCT_SELF_CONTAINED,T,N,p);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, N))) {   \
			struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uintptr_t)p);	\
			if (!__inode) {	\
				int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
				if (err) {	\
					DBGS("FLATTEN_STRUCT_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_##T(KFLAT_ACCESSOR,(p)));	\
					if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
			else {	\
				struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)p,\
						(uintptr_t)p+N-1);    \
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,make_flatten_pointer(KFLAT_ACCESSOR,__node,(uintptr_t)p-__node->start));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("FLATTEN_STRUCT_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
		}	\
		else DBGS("FLATTEN_STRUCT_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_STRUCT_TYPE_SELF_CONTAINED(T,N,p)	\
	do {	\
		DBGTNP(FLATTEN_STRUCT_TYPE_SELF_CONTAINED,T,N,p);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, N))) {   \
			struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uintptr_t)p);	\
			if (!__inode) {	\
				int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
				if (err) {	\
					DBGS("FLATTEN_STRUCT_TYPE_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_type_##T(KFLAT_ACCESSOR,(p)));	\
					if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_TYPE_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
			else {	\
				struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)p,\
						(uintptr_t)p+N-1);    \
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,make_flatten_pointer(KFLAT_ACCESSOR,__node,(uintptr_t)p-__node->start));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("FLATTEN_STRUCT_TYPE_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
		}	\
		else DBGS("FLATTEN_STRUCT_TYPE_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_STRUCT_ITER_SELF_CONTAINED(T,N,p)	\
	do {    \
        DBGTNP(FLATTEN_STRUCT_ITER_SELF_CONTAINED,T,N,p);  \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, N))) {   \
			struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uintptr_t)p);	\
			if (!__inode) {	\
				int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
				if (err) {	\
					DBGS("FLATTEN_STRUCT_ITER_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_iter_##T(KFLAT_ACCESSOR,(p),__q));	\
					if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
			else {	\
				struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)p,\
						(uintptr_t)p+N-1);    \
				if (__node==0) {	\
					KFLAT_ACCESSOR->errno = EFAULT;	\
				}	\
				else {	\
					int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,make_flatten_pointer(KFLAT_ACCESSOR,__node,(uintptr_t)p-__node->start));	\
					if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("FLATTEN_STRUCT_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
    } while(0)

#define FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED(T,N,p)	\
	do {    \
        DBGTNP(FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED,T,N,p);  \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, N))) {   \
			struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uintptr_t)p);	\
			if (!__inode) {	\
				int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
				if (err) {	\
					DBGS("FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_type_iter_##T(KFLAT_ACCESSOR,(p),__q));	\
					if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
			else {	\
				struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)p,\
						(uintptr_t)p+N-1);    \
				if (__node==0) {	\
					KFLAT_ACCESSOR->errno = EFAULT;	\
				}	\
				else {	\
					int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,make_flatten_pointer(KFLAT_ACCESSOR,__node,(uintptr_t)p-__node->start));	\
					if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
    } while(0)

#define FLATTEN_STRUCT_ARRAY(T,p,n)	\
	do {	\
		DBGM3(FLATTEN_STRUCT_ARRAY,T,p,n);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n) * sizeof(struct T)))) {   \
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_array_##T(KFLAT_ACCESSOR,(p),(n)));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_STRUCT_ARRAY: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_STRUCT_TYPE_ARRAY(T,p,n)	\
	do {	\
		DBGM3(FLATTEN_STRUCT_TYPE_ARRAY,T,p,n);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n) * sizeof(T)))) {   \
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_struct_type_array_##T(KFLAT_ACCESSOR,(p),(n)));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_STRUCT_TYPE_ARRAY: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_STRUCT_ARRAY_ITER(T,p,n)	\
	do {	\
		DBGM3(FLATTEN_STRUCT_ARRAY_ITER,T,p,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n) * sizeof(struct T)))) {	\
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,	\
					flatten_plain_type(KFLAT_ACCESSOR,p,(n)*sizeof(struct T)));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				DBGS("FLATTEN_STRUCT_ARRAY_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
			else {	\
				if (!err || (err==EAGAIN) || (err=EINVAL)) {	\
					struct fixup_set_node* __struct_inode;	\
					size_t _i;	\
					err = 0;	\
					for (_i=0; _i<(n); ++_i) {	\
						__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*sizeof(struct T)));	\
						if (!__struct_inode) {	\
							struct flatten_job __job;   \
							int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*sizeof(struct T)));	\
							if (err) break;	\
							__job.node = 0;    \
							__job.offset = 0; \
							__job.size = 1;	\
							__job.ptr = (struct flatten_base*)((void*)p+_i*sizeof(struct T));    \
							__job.fun = &flatten_struct_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_STRUCT_ARRAY_ITER_SPECIALIZE(TAG,T,p,n)	\
	do {	\
		DBGM3(FLATTEN_STRUCT_ARRAY_ITER_SPECIALIZE,T,p,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n) * sizeof(struct T)))) {	\
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,	\
					flatten_plain_type(KFLAT_ACCESSOR,p,(n)*sizeof(struct T)));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				DBGS("FLATTEN_STRUCT_ARRAY_ITER_SPECIALIZE:fixup_set_insert_force_update(): err(%d)\n",err);	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
			else {	\
				if (!err || (err==EAGAIN) || (err=EINVAL)) {	\
					struct fixup_set_node* __struct_inode;	\
					size_t _i;	\
					err = 0;	\
					for (_i=0; _i<(n); ++_i) {	\
						__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*sizeof(struct T)));	\
						if (!__struct_inode) {	\
							struct flatten_job __job;   \
							int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*sizeof(struct T)));	\
							if (err) break;	\
							__job.node = 0;    \
							__job.offset = 0; \
							__job.size = 1;	\
							__job.ptr = (struct flatten_base*)((void*)p+_i*sizeof(struct T));    \
							__job.fun = (flatten_struct_t)&flatten_struct_array_iter_##T##_##TAG;    \
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
		else DBGS("FLATTEN_STRUCT_ARRAY_ITER_SPECIALIZE: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_STRUCT_TYPE_ARRAY_ITER(T,p,n)	\
	do {	\
		DBGM3(FLATTEN_STRUCT_TYPE_ARRAY_ITER,T,p,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n) * sizeof(T)))) {	\
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,	\
					flatten_plain_type(KFLAT_ACCESSOR,p,(n)*sizeof(T)));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				DBGS("FLATTEN_STRUCT_TYPE_ARRAY_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
			else {	\
				if (!err || (err==EAGAIN) || (err=EINVAL)) {	\
					struct fixup_set_node* __struct_inode;	\
					size_t _i;	\
					err = 0;	\
					for (_i=0; _i<(n); ++_i) {	\
						__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*sizeof(T)));	\
						if (!__struct_inode) {	\
							struct flatten_job __job;   \
							int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*sizeof(T)));	\
							if (err) break;	\
							__job.node = 0;    \
							__job.offset = 0; \
							__job.size = 1;	\
							__job.ptr = (struct flatten_base*)((void*)p+_i*sizeof(T));    \
							__job.fun = &flatten_struct_type_array_iter_##T;    \
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
		else DBGS("FLATTEN_STRUCT_TYPE_ARRAY_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(T,N,p,n)	\
	do {	\
		DBGM4(FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED,T,N,p,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n) * N))) {	\
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,	\
					flatten_plain_type(KFLAT_ACCESSOR,p,(n)*N));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				DBGS("FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
			else {	\
				if (!err || (err==EAGAIN) || (err=EINVAL)) {	\
					struct fixup_set_node* __struct_inode;	\
					size_t _i;	\
					err = 0;	\
					for (_i=0; _i<(n); ++_i) {	\
						__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*N));	\
						if (!__struct_inode) {	\
							struct flatten_job __job;   \
							int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*N));	\
							if (err) break;	\
							__job.node = 0;    \
							__job.offset = 0; \
							__job.size = 1;	\
							__job.ptr = (struct flatten_base*)((void*)p+_i*N);    \
							__job.fun = &flatten_struct_array_iter_##T;    \
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
		else DBGS("FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED(T,N,p,n)	\
	do {	\
		DBGM4(FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED,T,N,p,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n) * N))) {	\
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,	\
					flatten_plain_type(KFLAT_ACCESSOR,p,(n)*N));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				DBGS("FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
			else {	\
				if (!err || (err==EAGAIN) || (err=EINVAL)) {	\
					struct fixup_set_node* __struct_inode;	\
					size_t _i;	\
					err = 0;	\
					for (_i=0; _i<(n); ++_i) {	\
						__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*N));	\
						if (!__struct_inode) {	\
							struct flatten_job __job;   \
							int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*N));	\
							if (err) break;	\
							__job.node = 0;    \
							__job.offset = 0; \
							__job.size = 1;	\
							__job.ptr = (struct flatten_base*)((void*)p+_i*N);    \
							__job.fun = &flatten_union_array_iter_##T;    \
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
		else DBGS("FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(T,N,p,n)	\
	do {	\
		DBGM4(FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED,T,N,p,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n) * N))) {	\
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,	\
					flatten_plain_type(KFLAT_ACCESSOR,p,(n)*N));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				DBGS("FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
			else {	\
				if (!err || (err==EAGAIN) || (err=EINVAL)) {	\
					struct fixup_set_node* __struct_inode;	\
					size_t _i;	\
					err = 0;	\
					for (_i=0; _i<(n); ++_i) {	\
						__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*N));	\
						if (!__struct_inode) {	\
							struct flatten_job __job;   \
							int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)p+_i*N));	\
							if (err) break;	\
							__job.node = 0;    \
							__job.offset = 0; \
							__job.size = 1;	\
							__job.ptr = (struct flatten_base*)((void*)p+_i*N);    \
							__job.fun = &flatten_struct_type_array_iter_##T;    \
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
		else DBGS("FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT(T,f)	\
	do {	\
		DBGTF(AGGREGATE_FLATTEN_STRUCT,T,f,"%lx",(unsigned long)ATTR(f));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f), sizeof(struct T)))) {	\
    		size_t _off = offsetof(_container_type,f);	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
    		if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)ATTR(f));	\
				if (!__inode) {	\
					int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)ATTR(f));	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
								flatten_struct_##T(KFLAT_ACCESSOR,(const struct T*)ATTR(f)));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)ATTR(f),\
							(uintptr_t)ATTR(f)+sizeof(struct T)-1);    \
					if (__struct_node==0) {	\
						KFLAT_ACCESSOR->errno = EFAULT;	\
					}	\
					else {	\
						int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
							make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)ATTR(f)-__struct_node->start));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("FLATTEN_STRUCT_TYPE_ARRAY_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE(T,f)	\
	do {	\
		DBGTF(AGGREGATE_FLATTEN_STRUCT_TYPE,T,f,"%lx",(unsigned long)ATTR(f));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f), sizeof(T)))) {	\
    		size_t _off = offsetof(_container_type,f);	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(T*)-1);    \
    		if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)ATTR(f));	\
				if (!__inode) {	\
					int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)ATTR(f));	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
								flatten_struct_type_##T(KFLAT_ACCESSOR,(const T*)ATTR(f)));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)ATTR(f),\
							(uintptr_t)ATTR(f)+sizeof(T)-1);    \
					if (__struct_node==0) {	\
						KFLAT_ACCESSOR->errno = EFAULT;	\
					}	\
					else {	\
						int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
							make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)ATTR(f)-__struct_node->start));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_STORAGE(T,p)	\
	do {	\
		DBGTF(AGGREGATE_FLATTEN_STRUCT_STORAGE,T,p,"%lx",(unsigned long)p);	\
    	if (!KFLAT_ACCESSOR->errno) {	\
    		struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)p);	\
    		if (!__inode) {	\
    			int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
    			if (!err) {	\
    				flatten_struct_##T(KFLAT_ACCESSOR,(const struct T*)p);	\
    			}	\
				if ((err) && (err!=EEXIST)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
    		}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_STORAGE: errno(%d)\n",KFLAT_ACCESSOR->errno);	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE(T,p)	\
	do {	\
		DBGTF(AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE,T,p,"%lx",(unsigned long)p);	\
    	if (!KFLAT_ACCESSOR->errno) {	\
    		struct fixup_set_node* __inode = fixup_set_search((uint64_t)p);	\
    		if (!__inode) {	\
    			int err = fixup_set_reserve_address((uintptr_t)p);	\
    			if (!err) {	\
    				flatten_struct_type_##T(KFLAT_ACCESSOR,(const struct T*)p);	\
    			}	\
				if ((err) && (err!=EEXIST)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
    		}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE: errno(%d)\n",KFLAT_ACCESSOR->errno);	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ITER(T,f)	\
	do {    \
        DBGTF(AGGREGATE_FLATTEN_STRUCT_ITER,T,f,"%lx",(unsigned long)ATTR(f));    \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f), sizeof(struct T)))) {  \
        	size_t _off = offsetof(_container_type,f);  \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				DBGS("AGGREGATE_FLATTEN_STRUCT_ITER: (__node==%d)\n",0);	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)ATTR(f));	\
				struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)ATTR(f),\
						(uintptr_t)ATTR(f)+sizeof(struct T)-1);    \
				if ((!__inode)||(__struct_node==0)) {	\
					int err = 0;	\
					if (!__inode) {	\
						err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)ATTR(f));	\
					}	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_ITER:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						struct flatten_job __job;   \
						int err;	\
						__job.node = __node;    \
						__job.offset = (uint64_t)_ptr-__node->start+_off; \
						__job.size = 1;	\
						__job.ptr = (struct flatten_base*)ATTR(f);    \
						__job.fun = &flatten_struct_array_iter_##T;    \
						__job.fp = 0;   \
						__job.convert = 0;  \
						err = bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
						if (err) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_ITER: bqueue_push_back(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)ATTR(f)-__struct_node->start));	\
					if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRUCT_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ITER(T,f)	\
	do {    \
        DBGTF(AGGREGATE_FLATTEN_STRUCT_TYPE_ITER,T,f,"%lx",(unsigned long)ATTR(f));    \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f), sizeof(T)))) {  \
        	size_t _off = offsetof(_container_type,f);  \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER: (__node==%d)\n",0);	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)ATTR(f));	\
				struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)ATTR(f),\
						(uintptr_t)ATTR(f)+sizeof(T)-1);    \
				if ((!__inode)||(__struct_node==0)) {	\
					int err = 0;	\
					if (!__inode) {	\
						err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)ATTR(f));	\
					}	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						struct flatten_job __job;   \
						int err;	\
						__job.node = __node;    \
						__job.offset = (uint64_t)_ptr-__node->start+_off; \
						__job.size = 1;	\
						__job.ptr = (struct flatten_base*)ATTR(f);    \
						__job.fun = &flatten_struct_type_array_iter_##T;    \
						__job.fp = 0;   \
						__job.convert = 0;  \
						err = bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
						if (err) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER: bqueue_push_back(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)ATTR(f)-__struct_node->start));	\
					if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_STORAGE_ITER(T,p)	\
	do {	\
		DBGTF(AGGREGATE_FLATTEN_STRUCT_STORAGE_ITER,T,p,"%lx",(unsigned long)p);	\
    	if (!KFLAT_ACCESSOR->errno) {	\
    		struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)p);	\
    		if (!__inode) {	\
    			int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
    			if (!err) {	\
    				struct flatten_job __job;   \
					__job.node = 0;    \
					__job.offset = 0; \
					__job.size = 1;	\
					__job.ptr = (struct flatten_base*)p;    \
					__job.fun = &flatten_struct_array_iter_##T;    \
					__job.fp = 0;   \
					__job.convert = 0;  \
					bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
    			}	\
				if ((err) && (err!=EEXIST)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
    		}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_STORAGE_ITER: errno(%d)\n",KFLAT_ACCESSOR->errno);	\
    } while(0)

#define AGGREGATE_FLATTEN_UNION_STORAGE_ITER(T,p)	\
	do {	\
		DBGTF(AGGREGATE_FLATTEN_UNION_STORAGE_ITER,T,p,"%lx",(unsigned long)p);	\
    	if (!KFLAT_ACCESSOR->errno) {	\
    		struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)p);	\
    		if (!__inode) {	\
    			int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
    			if (!err) {	\
    				struct flatten_job __job;   \
					__job.node = 0;    \
					__job.offset = 0; \
					__job.size = 1;	\
					__job.ptr = (struct flatten_base*)p;    \
					__job.fun = &flatten_union_array_iter_##T;    \
					__job.fp = 0;   \
					__job.convert = 0;  \
					bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
    			}	\
				if ((err) && (err!=EEXIST)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
    		}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_UNION_STORAGE_ITER: errno(%d)\n",KFLAT_ACCESSOR->errno);	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_ITER(T,p)	\
	do {    \
		DBGTF(AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_ITER,T,p,"%lx",(unsigned long)p);	\
    	if (!KFLAT_ACCESSOR->errno) {	\
    		struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)p);	\
    		if (!__inode) {	\
    			int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)p);	\
    			if (!err) {	\
    				struct flatten_job __job;   \
					__job.node = 0;    \
					__job.offset = 0; \
					__job.size = 1;	\
					__job.ptr = (struct flatten_base*)p;    \
					__job.fun = &flatten_struct_type_array_iter_##T;    \
					__job.fp = 0;   \
					__job.convert = 0;  \
					bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
    			}	\
				if ((err) && (err!=EEXIST)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
    		}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_ITER: errno(%d)\n",KFLAT_ACCESSOR->errno);	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER(T,f,pre_f,post_f)	\
	do {	\
		/* Beware here, pre_f() and post_f() should return 0 when NULL arguments passed */	\
		const struct T* _fp;	\
		DBGTFMF(AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER,T,f,"%lx",(unsigned long)ATTR(f),pre_f,post_f);	\
		_fp = pre_f((const struct T*)ATTR(f));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,sizeof(struct T)))) {	\
    		size_t _off = offsetof(_container_type,f);	\
			struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)_fp);	\
				if (!__inode) {	\
					int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)_fp);	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
								post_f(flatten_struct_##T(KFLAT_ACCESSOR,_fp),(const struct T*)ATTR(f)));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)_fp,\
							(uintptr_t)_fp+sizeof(struct T)-1);    \
					if (__struct_node==0) {	\
						KFLAT_ACCESSOR->errno = EFAULT;	\
					}	\
					else {	\
						int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
							make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)_fp-__struct_node->start));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)_fp);	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER(T,f,pre_f,post_f)	\
	do {	\
		/* Beware here, pre_f() and post_f() should return 0 when NULL arguments passed */	\
		const struct T* _fp;	\
		DBGTFMF(AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER,T,f,"%lx",(unsigned long)ATTR(f),pre_f,post_f);	\
		_fp = pre_f((const T*)ATTR(f));	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,sizeof(T)))) {	\
			size_t _off = offsetof(_container_type,f);	\
			struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)_fp);	\
				if (!__inode) {	\
					int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)_fp);	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
								post_f(flatten_struct_type_##T(KFLAT_ACCESSOR,_fp),(const T*)ATTR(f)));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)_fp,\
							(uintptr_t)_fp+sizeof(T)-1);    \
					if (__struct_node==0) {	\
						KFLAT_ACCESSOR->errno = EFAULT;	\
					}	\
					else {	\
						int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
							make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)_fp-__struct_node->start));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(_fp));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_STORAGE_MIXED_POINTER(T,p)	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_MIXED_POINTER(T,p)	\
	do {    \
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER(T,f,pre_f,post_f)	\
	do {    \
		const struct T* _fp;	\
		DBGTFMF(AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER,T,f,"%lx",(unsigned long)ATTR(f),pf,ff);  \
		_fp = pre_f((const struct T*)ATTR(f)); \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,sizeof(struct T)))) {  \
        	size_t _off = offsetof(_container_type,f);  \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)_fp);	\
				struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)_fp,\
						(uintptr_t)_fp+sizeof(struct T)-1);    \
				if ((!__inode)||(__struct_node==0)) {	\
					int err = 0;	\
					if (!__inode) {	\
						err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)_fp);	\
					}	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						struct flatten_job __job;   \
						int err;	\
						__job.node = __node;    \
						__job.offset = (uint64_t)_ptr-__node->start+_off; \
						__job.size = 1;	\
						__job.ptr = (struct flatten_base*)ATTR(f);    \
						__job.fun = &flatten_struct_array_iter_##T;    \
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
						DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)_fp);	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER(T,f,pre_f,post_f)	\
	do {    \
		const struct T* _fp;	\
		DBGTFMF(AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER,T,f,"%lx",(unsigned long)ATTR(f),pf,ff);  \
		_fp = pre_f((const T*)ATTR(f)); \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,sizeof(T)))) {  \
        	size_t _off = offsetof(_container_type,f);  \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)_fp);	\
				struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)_fp,\
						(uintptr_t)_fp+sizeof(T)-1);    \
				if ((!__inode)||(__struct_node==0)) {	\
					int err = 0;	\
					if (!__inode) {	\
						err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)_fp);	\
					}	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						struct flatten_job __job;   \
						int err;	\
						__job.node = __node;    \
						__job.offset = (uint64_t)_ptr-__node->start+_off; \
						__job.size = 1;	\
						__job.ptr = (struct flatten_base*)ATTR(f);    \
						__job.fun = &flatten_struct_type_array_iter_##T;    \
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
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(_fp));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_STORAGE_MIXED_POINTER_ITER(T,p)	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_MIXED_POINTER_ITER(T,p)	\
	do {    \
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY(T,f,n)	\
	do {	\
		DBGM3(AGGREGATE_FLATTEN_STRUCT_ARRAY,T,f,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f), (n)*sizeof(struct T)))) {	\
    		size_t _off = offsetof(_container_type,f);	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,ATTR(f),(n)*sizeof(struct T)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN)) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						err = 0;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)ATTR(f)+_i*sizeof(struct T)),(uint64_t)((void*)ATTR(f)+(_i+1)*sizeof(struct T)-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)ATTR(f)+_i*sizeof(struct T)));	\
							if (!__struct_inode) {	\
								void* _fp;	\
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)ATTR(f)+_i*sizeof(struct T)));	\
								if (err) break;	\
								_fp = (void*)flatten_struct_##T(KFLAT_ACCESSOR,(void*)ATTR(f)+_i*sizeof(struct T));	\
								kflat_free(_fp);	\
							}	\
						}	\
						if ((err) && (err!=EEXIST)) {	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY(T,f,n)	\
	do {	\
		DBGM3(AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY,T,f,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f), (n)*sizeof(T)))) {	\
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
					DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN)) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						err = 0;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)ATTR(f)+_i*sizeof(T)),(uint64_t)((void*)ATTR(f)+(_i+1)*sizeof(T)-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)ATTR(f)+_i*sizeof(T)));	\
							if (!__struct_inode) {	\
								void* _fp;	\
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)ATTR(f)+_i*sizeof(T)));	\
								if (err) break;	\
								_fp = (void*)flatten_struct_type_##T(KFLAT_ACCESSOR,(void*)ATTR(f)+_i*sizeof(T));	\
								kflat_free(_fp);	\
							}	\
						}	\
						if ((err) && (err!=EEXIST)) {	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER(T,f,n)	\
	do {	\
		DBGM3(AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER,T,f,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f),(n)*sizeof(struct T)))) {	\
    		size_t _off = offsetof(_container_type,f);  \
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,ATTR(f),(n)*sizeof(struct T)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN)) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						err = 0;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)ATTR(f)+_i*sizeof(struct T)),(uint64_t)((void*)ATTR(f)+(_i+1)*sizeof(struct T)-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)ATTR(f)+_i*sizeof(struct T)));	\
							if (!__struct_inode) {	\
								struct flatten_job __job;   \
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)ATTR(f)+_i*sizeof(struct T)));	\
								if (err) break;	\
								__job.node = 0;    \
								__job.offset = 0; \
								__job.size = 1;	\
								__job.ptr = (struct flatten_base*)((void*)ATTR(f)+_i*sizeof(struct T));    \
								__job.fun = &flatten_struct_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER(T,f,n)	\
	do {	\
		DBGM3(AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER,T,f,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f),(n)*sizeof(T)))) {	\
    		size_t _off = offsetof(_container_type,f);  \
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,ATTR(f),(n)*sizeof(T)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						err = 0;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)ATTR(f)+_i*sizeof(T)),(uint64_t)((void*)ATTR(f)+(_i+1)*sizeof(T)-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)ATTR(f)+_i*sizeof(T)));	\
							if (!__struct_inode) {	\
								struct flatten_job __job;   \
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)ATTR(f)+_i*sizeof(T)));	\
								if (err) break;	\
								__job.node = 0;    \
								__job.offset = 0; \
								__job.size = 1;	\
								__job.ptr = (struct flatten_base*)((void*)ATTR(f)+_i*sizeof(T));    \
								__job.fun = &flatten_struct_type_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
	} while(0)

/* We would probably want the following versions at some point in time as well:
 * AGGREGATE_FLATTEN_STRUCT_STORAGE_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_STORAGE_ARRAY_ITER
 * AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_ARRAY_ITER
 * AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_STORAGE_MIXED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_MIXED_POINTER_ARRAY
 * AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER
 * AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ARRAY_ITER
 * AGGREGATE_FLATTEN_STRUCT_STORAGE_MIXED_POINTER_ARRAY_ITER
 * AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_MIXED_POINTER_ARRAY_ITER
 */

#define AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(T,N,f,_off)	\
	do {	\
		DBGTNF(FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), N))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
    		if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)OFFATTR(void*,_off));	\
				if (!__inode) {	\
					int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)OFFATTR(void*,_off));	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
								flatten_struct_##T(KFLAT_ACCESSOR,(const struct T*)OFFATTR(void*,_off)));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)OFFATTR(void*,_off),\
							(uintptr_t)OFFATTR(void*,_off)+N-1);    \
					if (__struct_node==0) {	\
						KFLAT_ACCESSOR->errno = EFAULT;	\
					}	\
					else {	\
						int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
							make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)OFFATTR(void*,_off)-__struct_node->start));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(T,N,f,_off)	\
	do {	\
		DBGTNF(FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), N))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(T*)-1);    \
    		if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)OFFATTR(void*,_off));	\
				if (!__inode) {	\
					int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)OFFATTR(void*,_off));	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
								flatten_struct_type_##T(KFLAT_ACCESSOR,(const T*)OFFATTR(void*,_off)));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)OFFATTR(void*,_off),\
							(uintptr_t)OFFATTR(void*,_off)+N-1);    \
					if (__struct_node==0) {	\
						KFLAT_ACCESSOR->errno = EFAULT;	\
					}	\
					else {	\
						int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
							make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)OFFATTR(void*,_off)-__struct_node->start));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(T,N,f,_off)	\
	do {    \
        DBGTNF(FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off);    \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), N))) {  \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				DBGS("AGGREGATE_FLATTEN_STRUCT_ITER_SELF_CONTAINED: (__node==%d)\n",0);	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)OFFATTR(void*,_off));	\
				struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)OFFATTR(void*,_off),\
						(uintptr_t)OFFATTR(void*,_off)+N-1);    \
				if ((!__inode)||(__struct_node==0)) {	\
					int err = 0;	\
					if (!__inode) {	\
						err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)OFFATTR(void*,_off));	\
					}	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_ITER_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						struct flatten_job __job;   \
						int err;	\
						__job.node = __node;    \
						__job.offset = (uint64_t)_ptr-__node->start+_off; \
						__job.size = 1;	\
						__job.ptr = (struct flatten_base*)OFFATTR(void*,_off);    \
						__job.fun = &flatten_struct_array_iter_##T;    \
						__job.fp = 0;   \
						__job.convert = 0;  \
						err = bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
						if (err) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_ITER_SELF_CONTAINED: bqueue_push_back(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)OFFATTR(void*,_off)-__struct_node->start));	\
					if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRUCT_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED(T,N,f,_off)	\
	do {    \
        DBGTNF(AGGREGATE_FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off);    \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), N))) {  \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED: (__node==%d)\n",0);	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)OFFATTR(void*,_off));	\
				struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)OFFATTR(void*,_off),\
						(uintptr_t)OFFATTR(void*,_off)+N-1);    \
				if ((!__inode)||(__struct_node==0)) {	\
					int err = 0;	\
					if (!__inode) {	\
						err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)OFFATTR(void*,_off));	\
					}	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						struct flatten_job __job;   \
						int err;	\
						__job.node = __node;    \
						__job.offset = (uint64_t)_ptr-__node->start+_off; \
						__job.size = 1;	\
						__job.ptr = (struct flatten_base*)OFFATTR(void*,_off);    \
						__job.fun = &flatten_struct_type_array_iter_##T;    \
						__job.fp = 0;   \
						__job.convert = 0;  \
						err = bqueue_push_back(KFLAT_ACCESSOR,__q,&__job,sizeof(struct flatten_job));    \
						if (err) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED: bqueue_push_back(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)OFFATTR(void*,_off)-__struct_node->start));	\
					if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_SELF_CONTAINED(T,N,f,_off,pre_f,post_f)	\
	do {	\
		/* Beware here, pre_f() and post_f() should return 0 when NULL arguments passed */	\
		const struct T* _fp;	\
		DBGTNFOMF(AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off,pre_f,post_f);	\
		_fp = pre_f((const struct T*)OFFATTR(void*,_off));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,N))) {	\
			struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)_fp);	\
				if (!__inode) {	\
					int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)_fp);	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
								post_f(flatten_struct_##T(KFLAT_ACCESSOR,_fp),(const struct T*)OFFATTR(void*,_off)));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)_fp,\
							(uintptr_t)_fp+N-1);    \
					if (__struct_node==0) {	\
						KFLAT_ACCESSOR->errno = EFAULT;	\
					}	\
					else {	\
						int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
							make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)_fp-__struct_node->start));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)_fp);	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_SELF_CONTAINED(T,N,f,_off,pre_f,post_f)	\
	do {	\
		/* Beware here, pre_f() and post_f() should return 0 when NULL arguments passed */	\
		const struct T* _fp;	\
		DBGTNFOMF(AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off,pre_f,post_f);	\
		_fp = pre_f((const T*)OFFATTR(void*,_off));	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,N))) {	\
			struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				struct fixup_set_node* __inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)_fp);	\
				if (!__inode) {	\
					int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uintptr_t)_fp);	\
					if (err) {	\
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
								post_f(flatten_struct_type_##T(KFLAT_ACCESSOR,_fp),(const T*)OFFATTR(void*,_off)));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
				else {	\
					struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uintptr_t)_fp,\
							(uintptr_t)_fp+N-1);    \
					if (__struct_node==0) {	\
						KFLAT_ACCESSOR->errno = EFAULT;	\
					}	\
					else {	\
						int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
							make_flatten_pointer(KFLAT_ACCESSOR,__struct_node,(uintptr_t)_fp-__struct_node->start));	\
						if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
							DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)_fp);	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER_SELF_CONTAINED(T,N,f,_off,pre_f,post_f)	\
	do {    \
		const struct T* _fp;	\
		DBGTNFOMF(AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off,pf,ff);  \
		_fp = pre_f((const struct T*)OFFATTR(void*,_off)); \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,N))) {  \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
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
						DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						struct flatten_job __job;   \
						int err;	\
						__job.node = __node;    \
						__job.offset = (uint64_t)_ptr-__node->start+_off; \
						__job.size = 1;	\
						__job.ptr = (struct flatten_base*)OFFATTR(void*, _off);    \
						__job.fun = &flatten_struct_array_iter_##T;    \
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
						DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)_fp);	\
    } while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER_SELF_CONTAINED(T,N,f,_off,pre_f,post_f)	\
	do {    \
		const struct T* _fp;	\
		DBGTNFOMF(AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off,pf,ff);  \
		_fp = pre_f((const T*)OFFATTR(void*,_off)); \
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,N))) {  \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(T*)-1);    \
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
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER_SELF_CONTAINED:fixup_set_reserve_address(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
					else {	\
						struct flatten_job __job;   \
						int err;	\
						__job.node = __node;    \
						__job.offset = (uint64_t)_ptr-__node->start+_off; \
						__job.size = 1;	\
						__job.ptr = (struct flatten_base*)OFFATTR(void*, _off);    \
						__job.fun = &flatten_struct_type_array_iter_##T;    \
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
						DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
						KFLAT_ACCESSOR->errno = err;	\
					}	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_MIXED_POINTER_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)_fp);	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(T,N,f,_off,n)	\
	do {	\
		DBGM5(AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED,T,N,f,_off,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), (n)*N))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(void*,_off),(n)*N));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)OFFATTR(void*,_off)+_i*N),(uint64_t)((void*)OFFATTR(void*,_off)+(_i+1)*N-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)OFFATTR(void*,_off)+_i*N));	\
							if (!__struct_inode) {	\
								void* _fp;	\
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)OFFATTR(void*,_off)+_i*N));	\
								if (err) break;	\
								_fp = (void*)flatten_struct_##T(KFLAT_ACCESSOR,(void*)OFFATTR(void*,_off)+_i*N);	\
								kflat_free(_fp);	\
							}	\
						}	\
						if ((err) && (err!=EEXIST)) {	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(T,N,f,_off,n)	\
	do {	\
		DBGM5(AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED,T,N,f,_off,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), (n)*N))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(void*,_off),(n)*N));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN) {	\
						struct fixup_set_node* __struct_inode;	\
						size_t _i;	\
						for (_i=0; _i<(n); ++_i) {	\
							struct flat_node *__struct_node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root,	\
								(uint64_t)((void*)OFFATTR(void*,_off)+_i*N),(uint64_t)((void*)OFFATTR(void*,_off)+(_i+1)*N-1));    \
							if (__struct_node==0) {	\
								err = EFAULT;	\
								break;	\
							}	\
							__struct_inode = fixup_set_search(KFLAT_ACCESSOR,(uint64_t)((void*)OFFATTR(void*,_off)+_i*N));	\
							if (!__struct_inode) {	\
								void* _fp;	\
								int err = fixup_set_reserve_address(KFLAT_ACCESSOR,(uint64_t)((void*)OFFATTR(void*,_off)+_i*N));	\
								if (err) break;	\
								_fp = (void*)flatten_struct_type_##T(KFLAT_ACCESSOR,(void*)OFFATTR(void*,_off)+_i*N);	\
								kflat_free(_fp);	\
							}	\
						}	\
						if ((err) && (err!=EEXIST)) {	\
							KFLAT_ACCESSOR->errno = err;	\
						}	\
					}	\
				}	\
			}	\
		}	\
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(T,N,f,_off,n)	\
	do {	\
		DBGM5(AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED,T,N,f,_off,n);	\
		DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED [%lx:%zu -> %lx]\n",(uintptr_t)_ptr,(size_t)_off,(uintptr_t)OFFATTR(void*,_off));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), (n) * (N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(void*,_off),(n)*N));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN)) {	\
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
								__job.ptr = (struct flatten_base*)((void*)OFFATTR(void*,_off)+_i*N);    \
								__job.fun = &flatten_struct_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED(T,N,f,_off,n,_shift)	\
	do {	\
		DBGM6(AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED,T,N,f,_off,n,_shift);	\
		DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED [%lx:%zu -> %lx]\n",(uintptr_t)_ptr,(size_t)_off,(uintptr_t)OFFATTRN(void*,_off,_shift));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTRN(void*,_off,_shift), (n) * (N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err;	\
				struct flatten_pointer* __shifted = flatten_plain_type(KFLAT_ACCESSOR,OFFATTRN(void*,_off,_shift),(n)*N);	\
				struct flat_node* __ptr_node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uintptr_t)OFFATTR(void*,_off),	\
						(uintptr_t)OFFATTR(void*,_off)+1);	\
				__shifted->node = __ptr_node;	\
				__shifted->offset = (uintptr_t)OFFATTR(void*,_off) - __ptr_node->start;	\
				err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,__shifted);	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED:fixup_set_insert_force_update(): err(%d)\n",err);	\
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
								__job.fun = (flatten_struct_t)&flatten_struct_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED_SHIFTED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTRN(void*,_off,_shift));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED(T,N,f,_off,pre_f,post_f,n)	\
	do {	\
		const struct T* _fp;	\
		DBGTNFOMF(AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED,T,N,f,"%lx:%zu",(unsigned long)OFFATTR(void*,_off),(size_t)_off,pf,ff);  \
		_fp = pre_f((const T*)OFFATTR(void*,_off)); \
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,(n)*(N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						post_f(flatten_plain_type(KFLAT_ACCESSOR,_fp,(n)*N),(const T*)OFFATTR(void*,_off)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
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
								__job.fun = (flatten_struct_t)&flatten_struct_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED_SHIFTED(T,N,f,_off,pre_f,post_f,n,_shift)	\
	do {	\
		void* _p = pre_f((const struct T*)OFFATTR(void*,_off));	\
		const struct T* _fp = 0;	\
		if (_p) _fp = _p+_shift;	\
		DBGTNFOMF(AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED_SHIFTED,T,N,f,"%lx:%zu",_fp,(size_t)_off,pf,ff);  \
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(_fp,(n)*(N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(struct T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err;	\
				struct flatten_pointer* __shifted = flatten_plain_type(KFLAT_ACCESSOR,_fp,(n)*N);	\
				struct flat_node* __ptr_node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uintptr_t)_fp-_shift,(uintptr_t)_fp-_shift+1);	\
				__shifted->node = __ptr_node;	\
				__shifted->offset = (uintptr_t)_fp-_shift - __ptr_node->start;	\
				err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
					post_f(__shifted,(const struct T*)OFFATTR(void*,_off)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED_SHIFTED:fixup_set_insert_force_update(): err(%d)\n",err);	\
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
								__job.fun = (flatten_struct_t)&flatten_struct_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER_ARRAY_ITER_SELF_CONTAINED_SHIFTED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED(T,N,f,_off,n)	\
	do {	\
		DBGM5(AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED,T,N,f,_off,n);	\
		DBGS("AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED [%lx:%zu -> %lx]\n",(uintptr_t)_ptr,(size_t)_off,(uintptr_t)OFFATTR(void*,_off));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off),(n)*(N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(union T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(void*,_off),(n)*N));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN)) {	\
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
								__job.ptr = (struct flatten_base*)((void*)OFFATTR(void*,_off)+_i*N);    \
								__job.fun = &flatten_union_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED_SHIFTED(T,N,f,_off,n,_shift)	\
	do {	\
		DBGM6(AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED_SHIFTED,T,N,f,_off,n,_shift);	\
		DBGS("AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED_SHIFTED [%lx:%zu -> %lx]\n",(uintptr_t)_ptr,(size_t)_off,(uintptr_t)OFFATTRN(void*,_off,_shift));	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTRN(void*,_off,_shift),(n)*(N)))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(union T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err;	\
				struct flatten_pointer* __shifted = flatten_plain_type(KFLAT_ACCESSOR,OFFATTRN(void*,_off,_shift),(n)*N);	\
				struct flat_node* __ptr_node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uintptr_t)OFFATTR(void*,_off),	\
						(uintptr_t)OFFATTR(void*,_off)+1);	\
				__shifted->node = __ptr_node;	\
				__shifted->offset = (uintptr_t)OFFATTR(void*,_off) - __ptr_node->start;	\
				err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,__shifted);	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED_SHIFTED:fixup_set_insert_force_update(): err(%d)\n",err);	\
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
								__job.fun = (flatten_struct_t)&flatten_union_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_UNION_ARRAY_ITER_SELF_CONTAINED_SHIFTED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTRN(void*,_off,_shift));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED(T,N,f,_off,n)	\
	do {	\
		DBGM5(AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED,T,N,f,_off,n);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), (n)*N))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(void*,_off),(n)*N));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED:fixup_set_insert_force_update(): err(%d)\n",err);	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
				else {	\
					if (!err || (err==EAGAIN)) {	\
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
								__job.ptr = (struct flatten_base*)((void*)OFFATTR(void*,_off)+_i*N);    \
								__job.fun = &flatten_struct_type_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
	} while(0)

#define AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED_SHIFTED(T,N,f,_off,n,_shift)	\
	do {	\
		DBGM6(AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED_SHIFTED,T,N,f,_off,n,_shift);	\
    	if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTRN(void*,_off,_shift), (n) * N))) {	\
    		struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
    				(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err;	\
				struct flatten_pointer* __shifted = flatten_plain_type(KFLAT_ACCESSOR,OFFATTRN(void*,_off,_shift),(n)*N);	\
				struct flat_node* __ptr_node = interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uintptr_t)OFFATTR(void*,_off),	\
						(uintptr_t)OFFATTR(void*,_off)+1);	\
				__shifted->node = __ptr_node;	\
				__shifted->offset = (uintptr_t)OFFATTR(void*,_off) - __ptr_node->start;	\
				err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,__shifted);	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED_SHIFTED:fixup_set_insert_force_update(): err(%d)\n",err);	\
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
								__job.fun = (flatten_struct_t)&flatten_struct_type_array_iter_##T;    \
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
		else DBGS("AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_ITER_SELF_CONTAINED_SHIFTED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTRN(void*,_off,_shift));	\
	} while(0)

#define FLATTEN_TYPE(T,p)	\
	do {	\
		DBGM2(FLATTEN_TYPE,T,p);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, sizeof(T)))) {   \
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_plain_type(KFLAT_ACCESSOR,(p),sizeof(T)));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_TYPE: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)


#define FLATTEN_TYPE_ARRAY(T,p,n)	\
	do {	\
		DBGM3(FLATTEN_TYPE_ARRAY,T,p,n);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(p, (n)*sizeof(T)))) {   \
			int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__fptr->node,__fptr->offset,flatten_plain_type(KFLAT_ACCESSOR,(p),(n)*sizeof(T)));	\
			if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
				KFLAT_ACCESSOR->errno = err;	\
			}	\
		}	\
		else DBGS("FLATTEN_TYPE_ARRAY: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

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

#define AGGREGATE_FLATTEN_TYPE(T,f)	\
	do {  \
		DBGM2(AGGREGATE_FLATTEN_TYPE,T,f);	\
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(ATTR(f), sizeof(T)))) {   \
        	size_t _off = offsetof(_container_type,f);	\
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,ATTR(f),sizeof(T)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_TYPE: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
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

#define AGGREGATE_FLATTEN_STRING(f)	\
	do {  \
		DBGF(AGGREGATE_FLATTEN_STRING,f,"%lx",(unsigned long)ATTR(f));	\
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_VALID(ATTR(f)))) {   \
        	size_t _off = offsetof(_container_type,f);	\
			struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(char*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,ATTR(f),strmemlen(ATTR(f))));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_STRING: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
    } while(0)

#define AGGREGATE_FLATTEN_FUNCTION_POINTER(f)	\
	do {	\
		DBGF(AGGREGATE_FLATTEN_FUNCTION_POINTER,f,"%lx",(unsigned long)ATTR(f));	\
        if ((!KFLAT_ACCESSOR->errno)&&(TEXT_ADDR_VALID(ATTR(f)))) {   \
        	size_t _off = offsetof(_container_type,f);	\
			struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(int (*)(void))-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_fptr_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,(unsigned long)ATTR(f));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_FUNCTION_POINTER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)ATTR(f));	\
	} while (0)

#define AGGREGATE_FLATTEN_TYPE_SELF_CONTAINED(T,N,f,_off)	\
	do {  \
		DBGM4(AGGREGATE_FLATTEN_TYPE_SELF_CONTAINED,T,N,f,_off);	\
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), N))) {   \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
        			(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(void*,_off),(N)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_TYPE_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
    } while(0)

#define AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(T,f,_off,n)	\
	do {  \
		DBGM4(AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED,T,f,_off,n);	\
		DBGS("AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED[%lx]\n",(uintptr_t)OFFATTR(void*,_off));	\
        if ((!KFLAT_ACCESSOR->errno)&&(ADDR_RANGE_VALID(OFFATTR(void*,_off), (n) * sizeof(T)))) {   \
        	struct flat_node *__node = interval_tree_iter_first(&KFLAT_ACCESSOR->FLCTRL.imap_root, (uint64_t)_ptr+_off,\
					(uint64_t)_ptr+_off+sizeof(T*)-1);    \
			if (__node==0) {	\
				KFLAT_ACCESSOR->errno = EFAULT;	\
			}	\
			else {	\
				int err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__node,(uint64_t)_ptr-__node->start+_off,	\
						flatten_plain_type(KFLAT_ACCESSOR,OFFATTR(void*,_off),(n)*sizeof(T)));	\
				if ((err) && (err!=EEXIST) && (err!=EAGAIN)) {	\
					KFLAT_ACCESSOR->errno = err;	\
				}	\
			}	\
        }   \
		else DBGS("AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)OFFATTR(void*,_off));	\
    } while(0)

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


#define FLATTEN_FUNCTION_VARIABLE(__f,__var,__arg)	\
	do { 	\
			\
	}	\
	while(0);

#define FOR_POINTER(PTRTYPE,v,p,...)	\
	do {	\
		DBGM3(FOR_POINTER,PTRTYPE,v,p);	\
		DBGS("FOR_POINTER([%lx])\n",(uintptr_t)p);	\
		if ((!KFLAT_ACCESSOR->errno)&&(ADDR_VALID(p))) {	\
			PTRTYPE const * _m = (PTRTYPE const *)(p);	\
			struct flatten_pointer* __fptr = flatten_plain_type(KFLAT_ACCESSOR,_m,sizeof(void*));	\
			if (__fptr) {	\
				PTRTYPE v = *(_m);	\
				DBGS("FOR_POINTER(): *p=%lx\n",(uintptr_t)v);	\
				__VA_ARGS__;	\
				kflat_free(__fptr);	\
			}	\
			else {	\
				KFLAT_ACCESSOR->errno = ENOMEM;	\
			}	\
		}	\
		else DBGS("FOR_POINTER: errno(%d), ADDR(%lx)\n",KFLAT_ACCESSOR->errno,(uintptr_t)p);	\
	} while(0)

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

#define FOR_EXTENDED_ROOT_POINTER(p,__name,__size,...)	\
	do {	\
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
	} while(0)

#define FOR_ROOT_POINTER(p,...) FOR_EXTENDED_ROOT_POINTER(p, NULL, 0, ##__VA_ARGS__)

#define UNDER_ITER_HARNESS(...)	\
		do {	\
			struct bqueue bq;	\
			struct bqueue* __q;	\
			unsigned long __n;	\
			ktime_t __inittime;	\
			ktime_t __end;	\
			s64 __total_time = 0;	\
			int err = bqueue_init(KFLAT_ACCESSOR,&bq,DEFAULT_ITER_QUEUE_SIZE);	\
			if (err) {	\
				KFLAT_ACCESSOR->errno = err;	\
				break;	\
			}	\
			__q = &bq;	\
			__VA_ARGS__	\
			__n=0;	\
			__inittime = ktime_get();	\
			while((!KFLAT_ACCESSOR->errno)&&(!bqueue_empty(&bq))) {	\
				struct flatten_job __job;	\
				ktime_t __now;	\
				int err;	\
				DBGS("UNDER_ITER_HARNESS: queue iteration, size: %zu\n",bqueue_size(&bq));	\
				err = bqueue_pop_front(&bq,&__job,sizeof(struct flatten_job));	\
				if (err) {	\
					KFLAT_ACCESSOR->errno = err;	\
					break;	\
				}	\
				if (__job.node!=0) {	\
					if (!__job.convert)	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__job.node,__job.offset,(__job.fun)(KFLAT_ACCESSOR,__job.ptr,__job.size,&bq));	\
					else	\
						err = fixup_set_insert_force_update(KFLAT_ACCESSOR,__job.node,__job.offset,__job.convert((__job.fun)(KFLAT_ACCESSOR,__job.fp,__job.size,&bq),__job.ptr));	\
					if ((err) && (err!=EINVAL) && (err!=EEXIST) && (err!=EAGAIN)) {	\
						KFLAT_ACCESSOR->errno = err;	\
						break;	\
					}	\
				}	\
				else {	\
					void* _fp;	\
					if (!__job.convert)	\
						_fp = (__job.fun)(KFLAT_ACCESSOR,__job.ptr,__job.size,&bq);	\
					else	\
						_fp = __job.convert((__job.fun)(KFLAT_ACCESSOR,__job.fp,__job.size,&bq),__job.ptr);	\
					if (!_fp) break;	\
					kflat_free(_fp);	\
				}	\
				__n++;	\
				__now = ktime_get();	\
				DBGS("UNDER_ITER_HARNESS: recipes done: %lu, elapsed: %lld\n",__n,__now-__inittime);	\
				if (__now-__inittime>KFLAT_PING_TIME_NS) {	\
					__total_time+=__now-__inittime;	\
					flat_infos("Still working! done %lu recipes in total time %lld [ms], memory used: %zu, memory avail: %zu \n",	\
						__n,__total_time/TIME_MS,KFLAT_ACCESSOR->mptrindex,KFLAT_ACCESSOR->msize);	\
					__inittime = ktime_get();	\
				}	\
			}	\
			__end = ktime_get();	\
			__total_time+=__end-__inittime;	\
			flat_infos("Done working with %lu recipes in total time %lld [ms], memory used: %zu, memory avail: %zu \n",	\
				__n,__total_time/TIME_MS,KFLAT_ACCESSOR->mptrindex,KFLAT_ACCESSOR->msize);	\
			bqueue_destroy(&bq);	\
			bqueue_release_memory(KFLAT_ACCESSOR);	\
		} while(0)

#define GLOBAL_VARIABLE(MODULE_NAME, OFFSET)		flatten_global_address(MODULE_NAME, OFFSET)

#define PTRNODE(PTRV)	(interval_tree_iter_first(&kflat->FLCTRL.imap_root, (uintptr_t)(PTRV), (uintptr_t)(PTRV)))
#define KFLAT_ACCESSOR kflat

#endif /* _LINUX_KFLAT_H */

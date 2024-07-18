/**
 * @file flatten.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Header for feneric flattening code; base of both KFLAT and UFLAT
 * 
 */
#ifndef _HEADER_FLATTEN_H
#define _HEADER_FLATTEN_H

#ifdef __cplusplus
extern "C" {
#endif

/*************************************
 * DEFAULT CONFIGURATION
 *************************************/
#define LINEAR_MEMORY_ALLOCATOR					1
#define FLAT_LINEAR_MEMORY_INITIAL_POOL_SIZE	(256ULL * 1024 * 1024)
#define DEFAULT_ITER_QUEUE_SIZE					(8ULL * 1024 * 1024)
#define FLAT_PING_TIME_NS						(1 * NSEC_PER_SEC)
#define FLAT_MAX_TIME_NS						(8 * NSEC_PER_SEC)

struct flat;

/*************************************
 * BSP SPECIFIC CODE
 *************************************/
#include "flatten_port.h"
#include "flatten_image.h"


/*************************************
 * EXPORTED TYPES
 *************************************/
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

struct blstream {
	struct list_head head;
	const void* source;
	void* data;
	size_t size;
	size_t index;
	size_t alignment;
	size_t align_offset;
};

struct FLCONTROL {
	struct list_head storage_head;
	struct list_head root_addr_head;
	struct rb_root_cached fixup_set_root;
	struct rb_root_cached imap_root;
	struct flatten_header	HDR;
	struct root_addrnode* last_accessed_root;
	size_t root_addr_count;
	void* mem;

	int debug_flag;
	int mem_fragments_skip;
	int mem_copy_skip;
};

/* Fixup set */
enum fixup_encoding {
	FIXUP_DATA_POINTER		= 0,
	FIXUP_FUNC_POINTER		= 1
};

struct fixup_set_node {
	struct rb_node node;
  	/* Storage area and offset where the original address to be fixed is stored */
	struct flat_node* inode;
	size_t offset;
	/* Storage area and offset where the original address points to */
	struct flatten_pointer* ptr;

	enum fixup_encoding flags;
};

#define IS_FIXUP_FPTR(NODE)		((NODE)->flags & FIXUP_FUNC_POINTER)


/* Root address list */
struct root_addrnode {
	struct list_head head;
	uintptr_t root_addr;
	const char* name;
	size_t index;
	size_t size;
};

struct root_addr_set_node {
	struct rb_node node;
	char* name;
	uintptr_t root_addr;
};

struct queue_block {
	struct list_head head;
	unsigned char data[];
};

struct bqueue {
	struct list_head head;
	size_t block_size;
	size_t size;
	size_t front_index;
	size_t back_index;
	unsigned long el_count;
};

struct flat {
    struct FLCONTROL 	FLCTRL;
	struct rb_root		root_addr_set;
	int 				error;
	void*				_root_ptr;

	/* Iter jobs queue */
	struct bqueue 		bq;

	/* Destination area where dump will be saved */
    unsigned long		size;
	void				*area;

	/* Linear memory pool allocator support*/
	void*				mpool;
	size_t				mptrindex;
	size_t				msize;
};

struct flatten_base;

typedef struct flatten_pointer* (*flatten_struct_t)(struct flat* flat, const void*, size_t n, uintptr_t custom_val, unsigned long index, struct bqueue*);
typedef void* (*flatten_struct_embedded_extract_t)(const void *ptr);
typedef struct flatten_pointer* (*flatten_struct_embedded_convert_t)(struct flatten_pointer*, const struct flatten_base*);

typedef struct flatten_pointer* (*flatten_struct_iter_f)(struct flat* flat, const void* _ptr, struct bqueue* __q);
typedef struct flatten_pointer* (*flatten_struct_f)(struct flat* flat, const void* _ptr);


struct flatten_job {
    struct flat_node* node;
    size_t offset;
    size_t size;
    uintptr_t custom_val;
    unsigned long index;
    struct flatten_base* ptr;
    flatten_struct_t fun;
    /* Mixed pointer support */
    const struct flatten_base* fp;
    flatten_struct_embedded_convert_t convert;
};

#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)
INTERVAL_TREE_DEFINE(struct flat_node, rb,
		     uintptr_t, __subtree_last,
		     START, LAST, static __attribute__((used)),interval_tree);

/*************************************
 * EXPORTED FLATTEN FUNCTIONS
 *************************************/

void flatten_init(struct flat* flat);
int flatten_write(struct flat* flat);
int flatten_fini(struct flat* flat);

struct flatten_pointer* flatten_plain_type(struct flat* flat, const void* _ptr, size_t _sz);
int fixup_set_insert_force_update(struct flat* flat, struct flat_node* node, size_t offset, struct flatten_pointer* ptr);
int fixup_set_insert_fptr(struct flat* flat, struct flat_node* node, size_t offset, unsigned long fptr);
int fixup_set_insert_fptr_force_update(struct flat* flat, struct flat_node* node, size_t offset, unsigned long fptr);
int fixup_set_reserve_address(struct flat* flat, uintptr_t addr);
int fixup_set_reserve(struct flat* flat, struct flat_node* node, size_t offset);
int root_addr_append(struct flat* flat, size_t root_addr);
int root_addr_append_extended(struct flat* flat, size_t root_addr, const char* name, size_t size);
struct fixup_set_node* fixup_set_search(struct flat* flat, uintptr_t v);

int bqueue_init(struct flat* flat, struct bqueue* q, size_t block_size);
void bqueue_destroy(struct bqueue* q);
void bqueue_clear(struct bqueue* q);
int bqueue_push_back(struct flat* flat, struct bqueue* q, const void* m, size_t s);
int bqueue_pop_front(struct bqueue* q, void* m, size_t s);

void flatten_run_iter_harness(struct flat* flat);
void flatten_generic(struct flat* flat, void* q, struct flatten_pointer* fptr, const void* p, size_t el_size, size_t count, uintptr_t custom_val, flatten_struct_t func_ptr, unsigned long shift);
struct flat_node* flatten_acquire_node_for_ptr(struct flat* flat, const void* _ptr, size_t size);
void flatten_aggregate_generic(struct flat* flat, void* q, const void* _ptr, 
		size_t el_size, size_t count, uintptr_t custom_val, ssize_t _off, ssize_t _shift,
		flatten_struct_t func_ptr, flatten_struct_embedded_extract_t pre_f, flatten_struct_embedded_convert_t post_f);
void flatten_aggregate_generic_storage(struct flat* flat, void* q, const void* _ptr, 
		size_t el_size, size_t count, uintptr_t custom_val, ssize_t _off, flatten_struct_t func_ptr);


void* flat_zalloc(struct flat* flat, size_t size, size_t n);
void flat_free(void* p);



static inline struct flatten_pointer* make_flatten_pointer(struct flat* flat, struct flat_node* node, size_t offset) {
	struct flatten_pointer* v = (struct flatten_pointer*) flat_zalloc(flat, sizeof(struct flatten_pointer), 1);
	if (v==0) return 0;
	v->node = node;
	v->offset = offset;
	return v;
}

static inline void destroy_flatten_pointer(struct flatten_pointer* fp) {
	flat_free(fp->node->storage);
	flat_free(fp->node);
	flat_free(fp);
}


/*************************************
 * LOGGING
 *************************************/
#define flat_errs(fmt,...) 		do { FLATTEN_LOG_ERROR(fmt, ##__VA_ARGS__); FLATTEN_LOG_DEBUG("[ERROR] " fmt "\n", ##__VA_ARGS__); } while(0)
#define flat_infos(fmt,...) 	do { FLATTEN_LOG_INFO(fmt, ##__VA_ARGS__); FLATTEN_LOG_DEBUG("[INFO] " fmt, ##__VA_ARGS__); } while(0)
#define flat_dbg(fmt, ...)		do { if (FLAT_ACCESSOR->FLCTRL.debug_flag & 1) FLATTEN_LOG_DEBUG(fmt, ##__VA_ARGS__); } while(0)

#define DBGS(M, ...)						flat_dbg(M, ##__VA_ARGS__)
#define DBGM1(name,a1)						flat_dbg(#name "(" #a1 ")\n")
#define DBGOF(name,F,FMT,P,Q)				flat_dbg(#name "(" #F "[" FMT "])\n",P,Q)
#define DBGTNFOMF(name,T,N,F,FMT,P,Q,PF,FF) flat_dbg(#name "(" #T "," #N "," #F "[" FMT "]," #PF "," #FF ")\n",P,Q)
#define DBGM3(name,a1,a2,a3)				flat_dbg(#name "(" #a1 "," #a2 "," #a3 ")\n")
#define DBGM4(name,a1,a2,a3,a4)				flat_dbg(#name "(" #a1 "," #a2 "," #a3 "," #a4 ")\n")
#define DBGM5(name,a1,a2,a3,a4,a5)			flat_dbg(#name "(" #a1 "," #a2 "," #a3 "," #a4 "," #a5 ")\n")

/*************************************
 * HELPER MACROS
 *************************************/
#define STRUCT_ALIGN(n)		do { _alignment=n; } while(0)
#define ATTR(f)	((_ptr)->f)
/* Instead of calling 'p->member' you can access the member by its offset:
   MOFFATTR(p,typeof(member),offsetof(typeof(*p),member))
 */
#define MOFFATTR(p,T,offset)	(*((T*)((unsigned char*)(p)+offset)))
#define OFFATTR(T,_off)	MOFFATTR(_ptr,T,_off)
#define OFFATTRN(_off,_shift) (({	\
	void* p=*((void**)((unsigned char*)(_ptr)+_off));	\
	void* q = 0;	\
	if (p) q = p+_shift;	\
	q;	\
}))
#define OFFADDR(T,_off)	((T*)((unsigned char*)(_ptr)+_off))

#define FLATTEN_WRITE_ONCE(addr,wsize,wcounter_p)	do {	\
	if ((*(wcounter_p)+wsize)>flat->size) {	\
		flat->error = ENOMEM;		\
		return -1;			\
	}					\
	memcpy((char*)flat->area+(*(wcounter_p)),addr,wsize);	\
	*wcounter_p+=wsize;			\
} while(0);


#define PTRNODE(PTRV)	(interval_tree_iter_first(&flat->FLCTRL.imap_root, (uintptr_t)(PTRV), (uintptr_t)(PTRV)))
#define FLAT_ACCESSOR 	flat
#define __THIS_STRUCT (_ptr)
#define __ROOT_PTR (FLAT_ACCESSOR->_root_ptr)

/* Helper functions for recipes */
static inline void *ptr_clear_2lsb_bits(const void *ptr) {
	return (void *)((uintptr_t)ptr & ~3);
}

static inline struct flatten_pointer *flatten_ptr_restore_2lsb_bits(struct flatten_pointer *fptr, const struct flatten_base *ptr) {
	fptr->offset |= (size_t)((uintptr_t)ptr & 3);
	return fptr;
}


/* Definition of flatten recipes */
#include "flatten_recipe.h"

#ifdef __cplusplus
}
#endif

#endif

/**
 * @file example_fpointer.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

// Create forward-declaration of kflat userspace to avoid warning in userspace
// validator
#ifndef __TESTER__
struct flat;
#endif

// Common structure types
struct fptr_test_struct {
	void* (*alloc)(struct flat*, size_t, size_t);
	int (*set_reserve_address)(struct flat *flat, uintptr_t addr);
	int (*flatten_write)(struct flat* flat);
	void (*bqueue_clear)(void);
	void (*invalid)(void);
	int (*puts)(const char *);
	int kernel;
};

struct fptr_test_struct_2 {
	void* (*alloc)(struct flat*, size_t, size_t);
	int (*set_reserve_address)(struct flat *flat, uintptr_t addr);
	int (*flatten_write)(struct flat* flat);
	void (*bqueue_clear)(void);
	void (*invalid)(void);
	int (*puts)(const char *);
	int kernel;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(fptr_test_struct,
	AGGREGATE_FLATTEN_FUNCTION_POINTER(alloc);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(set_reserve_address);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(flatten_write);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(bqueue_clear);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(invalid);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(puts);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(fptr_test_struct_2, sizeof(struct fptr_test_struct_2),
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(alloc, offsetof(struct fptr_test_struct_2, alloc));
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(set_reserve_address, offsetof(struct fptr_test_struct_2, set_reserve_address));
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(flatten_write, offsetof(struct fptr_test_struct_2, flatten_write));
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(bqueue_clear, offsetof(struct fptr_test_struct_2, bqueue_clear));
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(invalid, offsetof(struct fptr_test_struct_2, invalid));
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(puts, offsetof(struct fptr_test_struct_2, puts));
);

static int kflat_fptr_test(struct flat *flat) {
	struct fptr_test_struct fptrs = {
		.alloc = flat_zalloc,
		.set_reserve_address = fixup_set_reserve_address,
		.flatten_write = flatten_write,
		.bqueue_clear = (void (*)(void))bqueue_clear,
		.invalid = (void *)flat,
#ifndef __KERNEL__
		.puts = puts,
		.kernel = 0,
#else
		.kernel = 1,
#endif
	};

	struct fptr_test_struct_2 fptrs_sc;

	FLATTEN_SETUP_TEST(flat);
	memcpy(&fptrs_sc, &fptrs, sizeof(fptrs));

	FOR_ROOT_POINTER(&fptrs,
		FLATTEN_STRUCT(fptr_test_struct, &fptrs);
	);

	FOR_ROOT_POINTER(&fptrs_sc,
		FLATTEN_STRUCT_SELF_CONTAINED(fptr_test_struct_2, sizeof(struct fptr_test_struct_2), &fptrs_sc);
	);

	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

// Instead of declaring these kernel function, let's use markers
//  to find one whether we're able to successfully match fptrs
#define TEST_MALLOC_ADDRESS (void *)0x1200
#define TEST_SET_RESERVE_ADDRESS (void *)0x1201
#define TEST_FLATTEN_WRITE_ADDRESS (void *)0x1202
#define TEST_BQUEUE_INIT (void *)0x1203
#define TEST_PUTS (void *)0x1204

bool match_kallsyms_name(const char* str, const char* prefix) {
	if(strncmp(str, prefix, strlen(prefix)))
		return false;

	char last = str[strlen(prefix)];
	return last == ' ' || last == '.' || last == '\0' || last == '\n';
}

// Match function name to local pointer
static uintptr_t kflat_fptr_gfa_handler(const char *fsym) {
	if (match_kallsyms_name(fsym, "flat_zalloc"))
		return (uintptr_t)TEST_MALLOC_ADDRESS;
	else if (match_kallsyms_name(fsym, "fixup_set_reserve_address"))
		return (uintptr_t)TEST_SET_RESERVE_ADDRESS;
	else if (match_kallsyms_name(fsym, "flatten_write"))
		return (uintptr_t)TEST_FLATTEN_WRITE_ADDRESS;
	else if (match_kallsyms_name(fsym, "bqueue_clear"))
		return (uintptr_t)TEST_BQUEUE_INIT;
	else if (match_kallsyms_name(fsym, "puts") || match_kallsyms_name(fsym, "_IO_puts"))
		return (uintptr_t)TEST_PUTS;
	return (uintptr_t)NULL;
}

static int kflat_fptr_validate(void *memory, size_t size, CUnflatten flatten) {
	struct fptr_test_struct *fptr = (struct fptr_test_struct *)unflatten_root_pointer_seq(flatten, 0);
	struct fptr_test_struct_2 *fptr_sc = (struct fptr_test_struct_2 *)unflatten_root_pointer_seq(flatten, 1);

	ASSERT(fptr->alloc == TEST_MALLOC_ADDRESS);
	ASSERT(fptr->set_reserve_address == TEST_SET_RESERVE_ADDRESS);
	ASSERT(fptr->flatten_write == TEST_FLATTEN_WRITE_ADDRESS);
	ASSERT(fptr->bqueue_clear == TEST_BQUEUE_INIT);
	if (!fptr->kernel)
		ASSERT(fptr->puts == TEST_PUTS);

	// ASSERT(fptr->invalid == NULL);

	ASSERT(fptr_sc->alloc == TEST_MALLOC_ADDRESS);
	ASSERT(fptr_sc->set_reserve_address == TEST_SET_RESERVE_ADDRESS);
	ASSERT(fptr_sc->flatten_write == TEST_FLATTEN_WRITE_ADDRESS);
	ASSERT(fptr_sc->bqueue_clear == TEST_BQUEUE_INIT);
	if (!fptr_sc->kernel)
		ASSERT(fptr_sc->puts == TEST_PUTS);

	// ASSERT(fptr_sc->invalid == NULL);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_GFA_FLAGS("FPOINTERS", kflat_fptr_test, kflat_fptr_validate, kflat_fptr_gfa_handler, KFLAT_TEST_ATOMIC);

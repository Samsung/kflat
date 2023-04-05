/**
 * @file example_fpointer.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

// Create forward-declaration of kflat userspace to avoid warning in userspace
// validator
#ifndef __KERNEL__
struct kflat;
#endif

// Common structure types
struct fptr_test_struct {
	void *(*alloc)(size_t);
	int (*set_reserve_address)(struct kflat *kflat, uintptr_t addr);
	struct blstream *(*stream_append)(struct kflat *kflat, const void *data, size_t size);
	void *(*global_address)(const char *);
	void (*invalid)(void);
};

struct fptr_test_struct_2 {
	void *(*alloc)(size_t);
	int (*set_reserve_address)(struct kflat *kflat, uintptr_t addr);
	struct blstream *(*stream_append)(struct kflat *kflat, const void *data, size_t size);
	void *(*global_address)(const char *);
	void (*invalid)(void);
};

/********************************/
#ifdef __KERNEL__
/********************************/

#include <linux/vmalloc.h>

FUNCTION_DEFINE_FLATTEN_STRUCT(fptr_test_struct,
	AGGREGATE_FLATTEN_FUNCTION_POINTER(alloc);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(set_reserve_address);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(stream_append);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(global_address);
	AGGREGATE_FLATTEN_FUNCTION_POINTER(invalid);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(fptr_test_struct_2, sizeof(struct fptr_test_struct_2),
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(alloc, offsetof(struct fptr_test_struct_2, alloc));
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(set_reserve_address, offsetof(struct fptr_test_struct_2, set_reserve_address));
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(stream_append, offsetof(struct fptr_test_struct_2, stream_append));
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(global_address, offsetof(struct fptr_test_struct_2, global_address));
	AGGREGATE_FLATTEN_FUNCTION_POINTER_SELF_CONTAINED(invalid, offsetof(struct fptr_test_struct_2, invalid));
);

static int kflat_fptr_test(struct kflat *kflat) {
	struct fptr_test_struct fptrs = {
		.alloc = vmalloc,
		.set_reserve_address = fixup_set_reserve_address,
		.stream_append = binary_stream_append,
		.global_address = flatten_global_address_by_name,
		.invalid = (void *)kflat
	};
	struct fptr_test_struct_2 fptrs_sc;
	memcpy(&fptrs_sc, &fptrs, sizeof(fptrs));

	FOR_ROOT_POINTER(&fptrs,
		FLATTEN_STRUCT(fptr_test_struct, &fptrs);
	);

	FOR_ROOT_POINTER(&fptrs_sc,
		FLATTEN_STRUCT_SELF_CONTAINED(fptr_test_struct_2, sizeof(struct fptr_test_struct_2), &fptrs_sc);
	);

	return 0;
}

/********************************/
#else
/********************************/

// Instead of declaring these kernel function, let's use markers
//  to find one whether we're able to successfully match fptrs
#define TEST_VMALLOC_ADDRESS (void *)0x1200
#define TEST_SET_RESERVE_ADDRESS (void *)0x1201
#define TEST_STREAM_APPEND_ADDRESS (void *)0x1202
#define TEST_FLATTEN_GLOBAL_ADDRESS (void *)0x1203

bool match_kallsyms_name(const char* str, const char* prefix) {
	if(strncmp(str, prefix, strlen(prefix)))
		return false;

	char last = str[strlen(prefix)];
	return last == ' ' || last == '.' || last == '\0' || last == '\n';
}

// Match function name to local pointer
static uintptr_t kflat_fptr_gfa_handler(const char *fsym) {
	if (match_kallsyms_name(fsym, "vmalloc"))
		return (uintptr_t)TEST_VMALLOC_ADDRESS;
	else if (match_kallsyms_name(fsym, "fixup_set_reserve_address"))
		return (uintptr_t)TEST_SET_RESERVE_ADDRESS;
	else if (match_kallsyms_name(fsym, "binary_stream_append"))
		return (uintptr_t)TEST_STREAM_APPEND_ADDRESS;
	else if (match_kallsyms_name(fsym, "flatten_global_address_by_name"))
		return (uintptr_t)TEST_FLATTEN_GLOBAL_ADDRESS;
	return (uintptr_t)NULL;
}

static int kflat_fptr_validate(void *memory, size_t size, CFlatten flatten) {
	struct fptr_test_struct *fptr = (struct fptr_test_struct *)flatten_root_pointer_seq(flatten, 0);
	struct fptr_test_struct_2 *fptr_sc = (struct fptr_test_struct_2 *)flatten_root_pointer_seq(flatten, 1);

	ASSERT(fptr->alloc == TEST_VMALLOC_ADDRESS);
	ASSERT(fptr->set_reserve_address == TEST_SET_RESERVE_ADDRESS);
	ASSERT(fptr->stream_append == TEST_STREAM_APPEND_ADDRESS);
	ASSERT(fptr->global_address == TEST_FLATTEN_GLOBAL_ADDRESS);
	ASSERT(fptr->invalid == NULL);

	ASSERT(fptr_sc->alloc == TEST_VMALLOC_ADDRESS);
	ASSERT(fptr_sc->set_reserve_address == TEST_SET_RESERVE_ADDRESS);
	ASSERT(fptr_sc->stream_append == TEST_STREAM_APPEND_ADDRESS);
	ASSERT(fptr_sc->global_address == TEST_FLATTEN_GLOBAL_ADDRESS);
	ASSERT(fptr_sc->invalid == NULL);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif
/********************************/

KFLAT_REGISTER_TEST_GFA_FLAGS("FPOINTERS", kflat_fptr_test, kflat_fptr_validate, kflat_fptr_gfa_handler, KFLAT_TEST_ATOMIC);

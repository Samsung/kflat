/**
 * @file unit_flatten_struct_type_self_contained.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

typedef struct {
	unsigned char T[4];
} typeB;

typedef struct {
	unsigned long X;
	typeB* pB;
} typeA;

typedef struct {
	char data[4097];
} typeL;

#ifdef __KERNEL__

#include <linux/vmalloc.h>

FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(typeA);
FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(typeB);
FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(typeL);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeB, sizeof(typeB));
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeA, sizeof(typeA),
	AGGREGATE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(
		typeB, sizeof(typeB), 0, offsetof(typeA, pB)
	);
);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeL, sizeof(typeL));

static int kflat_flatten_struct_type_self_contained_unit_test(struct kflat *kflat) {
	typeB str = { "CDF" };
	typeA obj = { 0xCAFECAFE, &str };
	typeA* pA = &obj;
	typeL* large = (typeL*) vmalloc(4096);

	FOR_ROOT_POINTER(pA,
		FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeA, sizeof(typeA), pA);
	);

	FOR_ROOT_POINTER(&str,
		FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeB, sizeof(typeB), &str);
	);

	FOR_ROOT_POINTER(large,
		FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeL, sizeof(typeL), large);
	);

	return 0;
}

#else

static int kflat_flatten_struct_type_self_contained_unit_validate(void* memory, size_t size, CFlatten flatten) {
	typeA* pA = (typeA*) flatten_root_pointer_seq(flatten, 0);
	typeB* str = (typeB*) flatten_root_pointer_seq(flatten, 1);

	ASSERT(pA->X == 0xCAFECAFE);
	ASSERT(pA->pB == str);
	ASSERT(!strcmp((const char*) str->T, "CDF"));
	return 0;
}

#endif


KFLAT_REGISTER_TEST("[UNIT] flatten_struct_type_self_contained", kflat_flatten_struct_type_self_contained_unit_test, kflat_flatten_struct_type_self_contained_unit_validate);
/**
 * @file unit_flatten_struct_type.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

typedef struct unit_A {
	unsigned long X;
	struct unit_B *pB;
} sA;

typedef struct unit_B {
	unsigned char T[4];
} sB;

typedef struct Large {
	char data[4097];
} sL;

#ifdef __KERNEL__

#include <linux/vmalloc.h>

FUNCTION_DECLARE_FLATTEN_STRUCT(unit_B);
FUNCTION_DECLARE_FLATTEN_STRUCT(unit_A);
FUNCTION_DECLARE_FLATTEN_STRUCT(Large);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(sB);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(sA,
	AGGREGATE_FLATTEN_STRUCT_TYPE(sB, pB);
);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(sL);

static int kflat_flatten_struct_type_unit_test(struct kflat *kflat) {
	struct unit_B str = { "ABC" };
	struct unit_A obj = { 0x0000404F, &str };
	struct unit_A *pA = &obj;
	struct Large *large = (struct Large *)vmalloc(4096);

	FOR_ROOT_POINTER(pA,
		FLATTEN_STRUCT_TYPE(sA, pA);
	);

	FOR_ROOT_POINTER(&str,
		FLATTEN_STRUCT_TYPE(sB, &str);
	);

	FOR_ROOT_POINTER(large,
		FLATTEN_STRUCT_TYPE(sL, large);
	);

	return 0;
}

#else

static int kflat_flatten_struct_type_unit_validate(void *memory, size_t size, CFlatten flatten) {
	struct unit_A *pA = (struct unit_A *)flatten_root_pointer_seq(flatten, 0);
	struct unit_B *str = (struct unit_B *)flatten_root_pointer_seq(flatten, 1);

	ASSERT(pA->X == 0x0000404F);
	ASSERT(pA->pB == str);
	ASSERT(!strcmp((const char *)str->T, "ABC"));
	return 0;
}

#endif

KFLAT_REGISTER_TEST("[UNIT] flatten_struct_type", kflat_flatten_struct_type_unit_test, kflat_flatten_struct_type_unit_validate);

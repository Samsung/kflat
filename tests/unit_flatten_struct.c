/**
 * @file unit_flatten_struct_array.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"


struct unit_A {
	unsigned long X;
	struct unit_B* pB;
};

struct unit_B {
	unsigned char T[4];
};

struct Large {
    char data[4097];
};

#ifdef __KERNEL__

#include <linux/vmalloc.h>

FUNCTION_DECLARE_FLATTEN_STRUCT(unit_B);
FUNCTION_DECLARE_FLATTEN_STRUCT(unit_A);
FUNCTION_DECLARE_FLATTEN_STRUCT(Large);

FUNCTION_DEFINE_FLATTEN_STRUCT(unit_B);
FUNCTION_DEFINE_FLATTEN_STRUCT(unit_A);
FUNCTION_DEFINE_FLATTEN_STRUCT(Large);

static int kflat_flatten_struct_unit_test(struct kflat *kflat) {
	struct unit_B str = { "ABC" };
	struct unit_A obj = { 0x0000404F, &str };
	struct unit_A* pA = &obj;
    struct Large* large = (struct Large*) vmalloc(4096);

	FOR_ROOT_POINTER(pA,
		FLATTEN_STRUCT(unit_A, pA);
	);

    FOR_ROOT_POINTER(&str,
        FLATTEN_STRUCT(unit_B, &str);
    );

    FOR_ROOT_POINTER(large,
        FLATTEN_STRUCT(Large, large);
    );

	return 0;
}

#else

static int kflat_flatten_struct_unit_validate(void* memory, size_t size, CFlatten flatten) {
    struct unit_A* pA = (struct unit_A*) flatten_root_pointer_seq(flatten, 0);
    struct unit_B* str = (struct unit_B*) flatten_root_pointer_seq(flatten, 1);

	ASSERT(pA->X == 0x0000404F);
	ASSERT(pA->pB != str);
    ASSERT(!strcmp((const char*) str->T, "ABC"));
	return 0;
}

#endif


KFLAT_REGISTER_TEST("[UNIT] flatten_struct", kflat_flatten_struct_unit_test, kflat_flatten_struct_unit_validate);

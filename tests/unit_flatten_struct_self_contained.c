/**
 * @file unit_flatten_struct_array.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct unit_sc_A {
	unsigned long X;
	struct unit_sc_B *pB;
};

struct unit_sc_B {
	unsigned char T[4];
};

struct unit_sc_Large {
	char data[4097];
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT(unit_sc_B);
FUNCTION_DECLARE_FLATTEN_STRUCT(unit_sc_A);
FUNCTION_DECLARE_FLATTEN_STRUCT(unit_sc_Large);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(unit_sc_B, sizeof(struct unit_sc_B));
FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(unit_sc_A, sizeof(struct unit_sc_A),
	AGGREGATE_FLATTEN_STRUCT_SELF_CONTAINED(unit_sc_B, sizeof(struct unit_sc_B), 0, offsetof(struct unit_sc_A, pB));
);
FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(unit_sc_Large, sizeof(struct unit_sc_Large));

static int kflat_flatten_struct_self_contained_unit_test(struct flat *flat) {
	int err;
	struct unit_sc_B str = { "CDF" };
	struct unit_sc_A obj = { 0xCAFECAFE, &str };
	struct unit_sc_A *pA = &obj;
	struct unit_sc_Large *large = (struct unit_sc_Large *)FLATTEN_BSP_VMA_ALLOC(4096);

	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(pA,
		FLATTEN_STRUCT_SELF_CONTAINED(unit_sc_A, sizeof(struct unit_sc_A), pA);
	);

	FOR_ROOT_POINTER(&str,
		FLATTEN_STRUCT_SELF_CONTAINED(unit_sc_B, sizeof(struct unit_sc_B), &str);
	);

	FOR_ROOT_POINTER(large,
		FLATTEN_STRUCT_SELF_CONTAINED(unit_sc_Large, sizeof(struct unit_sc_Large), large);
	);

	err = FLATTEN_FINISH_TEST(flat);

	FLATTEN_BSP_VMA_FREE(large, 4096);
	return err;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_struct_self_contained_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct unit_sc_A *pA = (struct unit_sc_A *)unflatten_root_pointer_seq(flatten, 0);
	struct unit_sc_B *str = (struct unit_sc_B *)unflatten_root_pointer_seq(flatten, 1);

	ASSERT(pA->X == 0xCAFECAFE);
	ASSERT(pA->pB == str);
	ASSERT(!strcmp((const char *)str->T, "CDF"));

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("[UNIT] flatten_struct_self_contained", kflat_flatten_struct_self_contained_unit_test, kflat_flatten_struct_self_contained_unit_validate, KFLAT_TEST_ATOMIC);

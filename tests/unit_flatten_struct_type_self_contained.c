/**
 * @file unit_flatten_struct_type_self_contained.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

typedef struct {
	unsigned char T[4];
} typeB;

typedef struct {
	unsigned long X;
	typeB *pB;
} typeA;

typedef struct {
	char data[4097];
} typeL;

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(typeA);
FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(typeB);
FUNCTION_DECLARE_FLATTEN_STRUCT_TYPE(typeL);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeB, sizeof(typeB));
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeA, sizeof(typeA),
	AGGREGATE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeB, sizeof(typeB), 0, offsetof(typeA, pB));
);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeL, sizeof(typeL));

static int kflat_flatten_struct_type_self_contained_unit_test(struct flat *flat) {
	int rv;
	typeB str = { "CDF" };
	typeA obj = { 0xCAFECAFE, &str };
	typeA *pA = &obj;
	typeL *large = (typeL *)FLATTEN_BSP_ZALLOC(4096);

	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(pA,
		FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeA, sizeof(typeA), pA);
	);

	FOR_ROOT_POINTER(&str,
		FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeB, sizeof(typeB), &str);
	);

	FOR_ROOT_POINTER(large,
		FLATTEN_STRUCT_TYPE_SELF_CONTAINED(typeL, sizeof(typeL), large);
	);

	rv = FLATTEN_FINISH_TEST(flat);

	FLATTEN_BSP_FREE(large);
	return rv;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_struct_type_self_contained_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	typeA *pA = (typeA *)unflatten_root_pointer_seq(flatten, 0);
	typeB *str = (typeB *)unflatten_root_pointer_seq(flatten, 1);

	ASSERT(pA->X == 0xCAFECAFE);
	ASSERT(pA->pB == str);
	ASSERT(!strcmp((const char *)str->T, "CDF"));

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] flatten_struct_type_self_contained", kflat_flatten_struct_type_self_contained_unit_test, kflat_flatten_struct_type_self_contained_unit_validate);

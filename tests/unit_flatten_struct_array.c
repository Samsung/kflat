/**
 * @file unit_flatten_struct_array.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

static const char *test_string = "THIS IS A TEST ";

struct element {
	int magic;
	char str[16];
};

struct container {
	struct element *tab;
	int *integers;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(element);

FUNCTION_DEFINE_FLATTEN_STRUCT(container,
	AGGREGATE_FLATTEN_STRUCT_ARRAY(element, tab, 3);
	AGGREGATE_FLATTEN_TYPE_ARRAY(int, integers, 10);
);

static int kflat_flatten_struct_array_unit_test(struct flat *flat) {
	int integers[10];
	struct element el[3];
	struct container box[2] = {
		{ el, integers }, { el + 1, integers + 4 }
	};

	FLATTEN_SETUP_TEST(flat);

	for (int i = 0; i < 10; i++)
		integers[i] = i * 2;
	for (int i = 0; i < 3; i++) {
		el[i].magic = 0xCAFECAFE + i;
		strcpy(el[i].str, test_string);
	}

	FOR_ROOT_POINTER(box,
		FLATTEN_STRUCT_ARRAY(container, box, 2);
	);

	// Test ADDR_RANGE_VALID macro
	FOR_ROOT_POINTER(box,
		FLATTEN_STRUCT_ARRAY(container, box, 10000);
	);

	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_struct_array_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct container *box = (struct container *)memory;

	ASSERT(box[0].integers + 4 == box[1].integers);
	ASSERT(box[0].tab + 1 == box[1].tab);

	for (int i = 0; i < 10; i++)
		ASSERT(box[0].integers[i] == i * 2);
	for (int i = 0; i < 3; i++) {
		ASSERT(box[0].tab[i].magic == 0xCAFECAFE + i);
		ASSERT(!strcmp(box[0].tab[i].str, test_string));
	}

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("[UNIT] flatten_struct_array", kflat_flatten_struct_array_unit_test, kflat_flatten_struct_array_unit_validate, KFLAT_TEST_ATOMIC);

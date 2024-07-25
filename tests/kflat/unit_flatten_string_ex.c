/**
 * @file unit_flatten_string_ex.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct str_ex_container {
	char *strLong;
	char *strInvalid;
	char *strNotTerminated;
	char* strNotAligned;
};

struct self_str_ex_container {
	char *strLong;
	char *strInvalid;
	char *strNotTerminated;
	char* strNotAligned;
};

/********************************/
#ifdef __TESTER__
/********************************/
#include <linux/vmalloc.h>

FUNCTION_DEFINE_FLATTEN_STRUCT(str_ex_container,
	AGGREGATE_FLATTEN_STRING(strLong);
	AGGREGATE_FLATTEN_STRING(strInvalid);
	AGGREGATE_FLATTEN_STRING(strNotTerminated);
	AGGREGATE_FLATTEN_STRING(strNotAligned);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(self_str_ex_container, sizeof(struct self_str_ex_container),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_ex_container, strLong));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_ex_container, strInvalid));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_ex_container, strNotTerminated));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_ex_container, strNotAligned));
);

static int kflat_flatten_string_ex_unit_test(struct flat *flat) {
	int rv;
	char *long_str = (char *)vmalloc(PAGE_SIZE * 2);
	char *long_str2 = (char *)vmalloc(PAGE_SIZE * 2);
	char* unterminated_str = (char *) vmalloc(PAGE_SIZE);

	struct str_ex_container str1 = {
		.strLong = long_str,
		.strInvalid = (char *)-1,
		.strNotTerminated = unterminated_str,
		.strNotAligned = long_str + 1,
	};
	struct self_str_ex_container str2 = {
		.strLong = long_str2,
		.strInvalid = (char *)-1,
		.strNotTerminated = unterminated_str,
		.strNotAligned = long_str2 + 1,
	};

	FLATTEN_SETUP_TEST(flat);

	for (size_t i = 0; i < PAGE_SIZE * 2 - 1; i++) {
		long_str[i] = 'A' + (i % 28);
		long_str2[i] = 'a' + (i % 28);
	}

	for(size_t i = 0; i < PAGE_SIZE; i++)
		unterminated_str[i] = 'A';

	FOR_ROOT_POINTER(&str1,
		FLATTEN_STRUCT(str_ex_container, &str1);
	);

	FOR_ROOT_POINTER(&str2,
		FLATTEN_STRUCT_SELF_CONTAINED(self_str_ex_container, sizeof(struct self_str_ex_container), &str2);
	);

	rv = FLATTEN_FINISH_TEST(flat);

	vfree(long_str);
	vfree(long_str2);
	vfree(unterminated_str);
	return rv;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_string_ex_validate(void *memory, size_t size, CUnflatten flatten) {
	struct str_ex_container *str1 = (struct str_ex_container *)unflatten_root_pointer_seq(flatten, 0);
	struct self_str_ex_container *str2 = (struct self_str_ex_container *)unflatten_root_pointer_seq(flatten, 1);

	ASSERT(str1->strInvalid == (char *)-1);
	ASSERT(str1->strNotAligned == str1->strLong + 1);

	ASSERT(str2->strInvalid == (char *)-1);
	ASSERT(str2->strNotAligned == str2->strLong + 1);

	for (size_t i = 0; i < 4096 * 2 - 1; i++) {
		ASSERT(str1->strLong[i] == 'A' + (i % 28));
		ASSERT(str2->strLong[i] == 'a' + (i % 28));
	}

	ASSERT(str1->strNotTerminated == str2->strNotTerminated);
	for(size_t i = 0; i < 4096; i++)
		ASSERT(str1->strNotTerminated[i] == 'A');

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] flatten_string_ex", kflat_flatten_string_ex_unit_test, kflat_flatten_string_ex_validate);

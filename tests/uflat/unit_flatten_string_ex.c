/**
 * @file unit_flatten_string_ex.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct str_ex_container {
	char *strLong;
	char* strVeryLong;
	char *strInvalid;
	char *strNotTerminated;
	char* strNotAligned;
};

struct self_str_ex_container {
	char *strLong;
	char* strVeryLong;
	char *strInvalid;
	char *strNotTerminated;
	char* strNotAligned;
};

/********************************/
#ifdef __TESTER__
/********************************/
#include <sys/mman.h>
#include <string.h>

FUNCTION_DEFINE_FLATTEN_STRUCT(str_ex_container,
	AGGREGATE_FLATTEN_STRING(strLong);
	AGGREGATE_FLATTEN_STRING(strInvalid);
	AGGREGATE_FLATTEN_STRING(strNotTerminated);
	AGGREGATE_FLATTEN_STRING(strNotAligned);
	AGGREGATE_FLATTEN_STRING(strVeryLong);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(self_str_ex_container, sizeof(struct self_str_ex_container),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_ex_container, strLong));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_ex_container, strInvalid));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_ex_container, strNotTerminated));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_ex_container, strNotAligned));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_ex_container, strVeryLong));
);

static int kflat_flatten_string_ex_unit_test(struct flat *flat) {
	char* strLong = malloc(10000);
	memset(strLong, 'A', 10000);
	strLong[9999] = '\0';

	char* strVeryLong = mmap(0, 1ULL * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	memset(strVeryLong, 'B', 1ULL * 1024 * 1024);
	strVeryLong[1ULL * 1024 * 1024 - 1] = '\0';

	char* strNotTerm = mmap(0, 16 * 1024, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	memset(strNotTerm, 'C', 16 * 1024);

	char strTest[100];
	memset(strTest, 'D', 100);
	strTest[99] = '\0';

	struct str_ex_container str1 = {
		.strLong = strLong,
		.strVeryLong = strVeryLong,
		.strInvalid = (char*) 0xaabb,
		.strNotTerminated = strNotTerm,
		.strNotAligned = strTest + 17
	};
	struct self_str_ex_container str2 = {
		.strLong = strLong,
		.strVeryLong = strVeryLong,
		.strInvalid = (char*) 0xaabb,
		.strNotTerminated = strNotTerm,
		.strNotAligned = strTest + 17
	};

	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(&str1,
		FLATTEN_STRUCT(str_ex_container, &str1);
	);

	FOR_ROOT_POINTER(&str2,
		FLATTEN_STRUCT_SELF_CONTAINED(self_str_ex_container, sizeof(struct self_str_ex_container), &str2);
	);

	free(strLong);
	munmap(strVeryLong, 1ULL * 1024 * 1024);
	munmap(strNotTerm, 16 * 1024);
	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static bool bytecmp(char* mem, char byte, size_t len) {
	for(size_t i = 0; i < len; i++)
		if(mem[i] != byte)
			return true;
	
	return false;
}

static int kflat_flatten_string_ex_validate(void *memory, size_t size, CUnflatten flatten) {
	struct str_ex_container *str1 = (struct str_ex_container *)unflatten_root_pointer_seq(flatten, 0);
	struct self_str_ex_container *str2 = (struct self_str_ex_container *)unflatten_root_pointer_seq(flatten, 1);

	ASSERT(str1->strInvalid == (char *)0xaabb);
	ASSERT(str2->strInvalid == (char *)0xaabb);

	ASSERT(!bytecmp(str1->strLong, 'A', 10000-1));
	ASSERT(!bytecmp(str2->strLong, 'A', 10000-1));

	ASSERT(!bytecmp(str1->strVeryLong, 'B', 1ULL * 1024 * 1024-1));
	ASSERT(!bytecmp(str2->strVeryLong, 'B', 1ULL * 1024 * 1024-1));

	ASSERT(!bytecmp(str1->strNotTerminated, 'C', 16 * 1024));
	ASSERT(!bytecmp(str2->strNotTerminated, 'C', 16 * 1024));

	ASSERT(!bytecmp(str1->strNotAligned, 'D',99-17));
	ASSERT(!bytecmp(str2->strNotAligned, 'D', 99-17));


	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] flatten_string_ex", kflat_flatten_string_ex_unit_test, kflat_flatten_string_ex_validate);

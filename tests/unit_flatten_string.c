/**
 * @file unit_flatten_string.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct str_container {
	char *str;
	char *strLong;
	char *strEmpty;
	char *strInvalid;
	char *sameAsFirst;
	char *strNotTerminated;
	char* strNotAligned;
	char* strMiddleEnded;
};

struct self_str_container {
	char *str;
	char *strLong;
	char *strEmpty;
	char *strInvalid;
	char *sameAsFirst;
	char *strNotTerminated;
	char* strNotAligned;
	char* strMiddleEnded;
};

/********************************/
#ifdef __TESTER__
/********************************/


FUNCTION_DEFINE_FLATTEN_STRUCT(str_container,
	AGGREGATE_FLATTEN_STRING(str);
	AGGREGATE_FLATTEN_STRING(strLong);
	AGGREGATE_FLATTEN_STRING(strEmpty);
	AGGREGATE_FLATTEN_STRING(strInvalid);
	AGGREGATE_FLATTEN_STRING(sameAsFirst);
	AGGREGATE_FLATTEN_STRING(strNotTerminated);
	AGGREGATE_FLATTEN_STRING(strNotAligned);
	AGGREGATE_FLATTEN_STRING(strMiddleEnded);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(self_str_container, sizeof(struct self_str_container),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, str));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, strLong));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, strEmpty));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, strInvalid));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, sameAsFirst));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, strNotTerminated));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, strNotAligned));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, strMiddleEnded));
);

static int kflat_flatten_string_unit_test(struct flat *flat) {
	int rv;
	char *long_str = (char *)FLATTEN_BSP_ZALLOC(PAGE_SIZE * 2);
	char *long_str2 = (char *)FLATTEN_BSP_ZALLOC(PAGE_SIZE * 2);
	char* unterminated_str = (char *) FLATTEN_BSP_ZALLOC(PAGE_SIZE);
	char* middle_ended_str = (char *) FLATTEN_BSP_ZALLOC(PAGE_SIZE * 10);

	struct str_container str1 = {
		.str = "Good morning!",
		.strLong = long_str,
		.strEmpty = "\0",
		.strInvalid = (char *)-1,
		.strNotTerminated = unterminated_str,
		.strNotAligned = long_str + 1,
		.strMiddleEnded = middle_ended_str
	};
	struct self_str_container str2 = {
		.str = "Good evening!",
		.strLong = long_str2,
		.strEmpty = "\0",
		.strInvalid = (char *)-1,
		.strNotTerminated = unterminated_str,
		.strNotAligned = long_str2 + 1,
		.strMiddleEnded = middle_ended_str
	};

	FLATTEN_SETUP_TEST(flat);

	str1.sameAsFirst = str1.str;
	str2.sameAsFirst = str2.str;

	for (size_t i = 0; i < PAGE_SIZE * 2 - 1; i++) {
		long_str[i] = 'A' + (i % 28);
		long_str2[i] = 'a' + (i % 28);
	}

	for(size_t i = 0; i < PAGE_SIZE; i++)
		unterminated_str[i] = 'A';

	for(size_t i = 0; i < PAGE_SIZE * 10 - 1; i++) {
		if(i == PAGE_SIZE * 5 + 17)
			middle_ended_str[i] = '\0';
		else
			middle_ended_str[i] = 'A' + (i % 28);
	}
	middle_ended_str[PAGE_SIZE * 10 - 1] = '\0';

	FOR_ROOT_POINTER(&str1,
		FLATTEN_STRUCT(str_container, &str1);
	);

	FOR_ROOT_POINTER(&str2,
		FLATTEN_STRUCT_SELF_CONTAINED(self_str_container, sizeof(struct self_str_container), &str2);
	);

	rv = FLATTEN_FINISH_TEST(flat);

	FLATTEN_BSP_FREE(long_str);
	FLATTEN_BSP_FREE(long_str2);
	FLATTEN_BSP_FREE(unterminated_str);
	return rv;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_string_validate(void *memory, size_t size, CUnflatten flatten) {
	struct str_container *str1 = (struct str_container *)unflatten_root_pointer_seq(flatten, 0);
	struct self_str_container *str2 = (struct self_str_container *)unflatten_root_pointer_seq(flatten, 1);

	ASSERT(!strcmp(str1->str, "Good morning!"));
	ASSERT(str1->str == str1->sameAsFirst);
	ASSERT(*str1->strEmpty == '\0');
	ASSERT(str1->strInvalid == (char *)-1);
	ASSERT(str1->strNotAligned == str1->strLong + 1);

	ASSERT(!strcmp(str2->str, "Good evening!"));
	ASSERT(str2->str == str2->sameAsFirst);
	ASSERT(*str2->strEmpty == '\0');
	ASSERT(str2->strInvalid == (char *)-1);
	ASSERT(str2->strNotAligned == str2->strLong + 1);

	for (size_t i = 0; i < 4096 * 2 - 1; i++) {
		ASSERT(str1->strLong[i] == 'A' + (i % 28));
		ASSERT(str2->strLong[i] == 'a' + (i % 28));
	}

	ASSERT(str1->strNotTerminated == str2->strNotTerminated);
	for(size_t i = 0; i < 4096; i++)
		ASSERT(str1->strNotTerminated[i] == 'A');

	for(size_t i = 0; i < 4096 * 10 - 1; i++) {
		if(i == 4096 * 5 + 17) {
			ASSERT(str1->strMiddleEnded[i] == '\0');
			ASSERT(str2->strMiddleEnded[i] == '\0');
		} else if(i > 4096 * 5 + 17) {
			break;
		}
		else {
			ASSERT(str1->strMiddleEnded[i] == 'A' + (i % 28));
			ASSERT(str2->strMiddleEnded[i] == 'A' + (i % 28));
		}
	}

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] flatten_string", kflat_flatten_string_unit_test, kflat_flatten_string_validate);

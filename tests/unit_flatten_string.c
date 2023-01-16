/**
 * @file unit_flatten_string.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct str_container {
	char *str;
	char *strLong;
	char *strEmpty;
	char *strInvalid;
	char *sameAsFirst;
};

struct self_str_container {
	char *str;
	char *strLong;
	char *strEmpty;
	char *strInvalid;
	char *sameAsFirst;
};

#ifdef __KERNEL__

#include <linux/vmalloc.h>

FUNCTION_DEFINE_FLATTEN_STRUCT(str_container,
	AGGREGATE_FLATTEN_STRING(str);
	AGGREGATE_FLATTEN_STRING(strLong);
	AGGREGATE_FLATTEN_STRING(strEmpty);
	AGGREGATE_FLATTEN_STRING(strInvalid);
	AGGREGATE_FLATTEN_STRING(sameAsFirst);
);

FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(self_str_container, sizeof(struct self_str_container),
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, str));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, strLong));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, strEmpty));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, strInvalid));
	AGGREGATE_FLATTEN_STRING_SELF_CONTAINED(0, offsetof(struct self_str_container, sameAsFirst));
);

static int kflat_flatten_string_unit_test(struct kflat *kflat) {
	char *long_str = (char *)vmalloc(PAGE_SIZE * 2);
	char *long_str2 = (char *)vmalloc(PAGE_SIZE * 2);

	struct str_container str1 = {
		.str = "Good morning!",
		.strLong = long_str,
		.strEmpty = "\0",
		.strInvalid = (char *)-1,
	};
	struct self_str_container str2 = {
		.str = "Good evening!",
		.strLong = long_str2,
		.strEmpty = "\0",
		.strInvalid = (char *)-1,
	};

	str1.sameAsFirst = str1.str;
	str2.sameAsFirst = str2.str;

	for (size_t i = 0; i < PAGE_SIZE * 2 - 1; i++) {
		long_str[i] = 'A' + (i % 28);
		long_str2[i] = 'a' + (i % 28);
	}

	FOR_ROOT_POINTER(&str1,
		FLATTEN_STRUCT(str_container, &str1);
	);

	FOR_ROOT_POINTER(&str2,
		FLATTEN_STRUCT_SELF_CONTAINED(self_str_container, sizeof(struct self_str_container), &str2);
	);

	return 0;
}

#else

static int kflat_flatten_string_validate(void *memory, size_t size, CFlatten flatten) {
	struct str_container *str1 = (struct str_container *)flatten_root_pointer_seq(flatten, 0);
	struct self_str_container *str2 = (struct self_str_container *)flatten_root_pointer_seq(flatten, 1);

	ASSERT(!strcmp(str1->str, "Good morning!"));
	ASSERT(str1->str == str1->sameAsFirst);
	ASSERT(*str1->strEmpty == '\0');
	ASSERT(str1->strInvalid == (char *)-1);

	ASSERT(!strcmp(str2->str, "Good evening!"));
	ASSERT(str2->str == str2->sameAsFirst);
	ASSERT(*str2->strEmpty == '\0');
	ASSERT(str2->strInvalid == (char *)-1);

	for (size_t i = 0; i < 4096 * 2 - 1; i++) {
		ASSERT(str1->strLong[i] == 'A' + (i % 28));
		ASSERT(str2->strLong[i] == 'a' + (i % 28));
	}

	return 0;
}

#endif

KFLAT_REGISTER_TEST("[UNIT] flatten_string", kflat_flatten_string_unit_test, kflat_flatten_string_validate);

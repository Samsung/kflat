/**
 * @file unit_aligned_root_pointer.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct test_structure {
	unsigned long long value;
	char x[3];
};


/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(test_structure);


static int kflat_aligned_root_pointers_test(struct flat *flat) {
	struct test_structure test1 = {1, {'a', 'b', 'c'}};
	struct test_structure test2 = {2, {'d', 'e', 'f'}};
	char* some_str = "te\0";
	struct test_structure test3 = {3, {'g', 'h', 'i'}};
	struct test_structure test4[3] = {{4, {'z', 'y', 'x'}}, {5, {'c', 'v', 'b'}}, {6, {'s', 'g', 'h'}}};
	struct test_structure test5 __attribute__((aligned (2))) = {7, {'m', 'i', 'j'}};

	FLATTEN_SETUP_TEST(flat);

	if(((uintptr_t) &test1) % (sizeof(unsigned long long)) != 0) {
		flat_errs("Local variable `test1` in test case %s is not aligned as expected", __func__);
		return 1;
	} else if(((uintptr_t) &test3) % (sizeof(unsigned long long)) != 0) {
		flat_errs("Local variable `test3` in test case %s is not aligned as expected", __func__);
		return 1;
	}

	FOR_EXTENDED_ROOT_POINTER(&test1, "test1", sizeof(test1),
		FLATTEN_STRUCT(test_structure, &test1);
	);

	FOR_EXTENDED_ROOT_POINTER(&test2, "test2", sizeof(test2),
		FLATTEN_STRUCT(test_structure, &test2);
	);

	FOR_EXTENDED_ROOT_POINTER(some_str, "some_str", strlen(some_str),
		FLATTEN_STRING(some_str);
	);

	FOR_EXTENDED_ROOT_POINTER(&test3, "test3", sizeof(test3),
		FLATTEN_STRUCT(test_structure, &test3);
	);

	FOR_EXTENDED_ROOT_POINTER(&test4, "test4", sizeof(test4),
		FLATTEN_STRUCT_ARRAY(test_structure, &test4, 3);
	);

	FOR_EXTENDED_ROOT_POINTER(&test5, "test5", sizeof(test5),
		FLATTEN_STRUCT(test_structure, &test5);
	);

	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_aligned_root_pointers_validate(void *memory, size_t size, CUnflatten flatten) {
	struct test_structure *test1 = (struct test_structure *)unflatten_root_pointer_named(flatten, "test1", NULL);
	struct test_structure *test2 = (struct test_structure *)unflatten_root_pointer_named(flatten, "test2", NULL);
	struct test_structure *test3 = (struct test_structure *)unflatten_root_pointer_named(flatten, "test3", NULL);
	struct test_structure *test5 = (struct test_structure *)unflatten_root_pointer_named(flatten, "test5", NULL);
	struct test_structure (*test4)[3] = (struct test_structure (*) [3])unflatten_root_pointer_named(flatten, "test4", NULL);
	char* some_str = (char*)unflatten_root_pointer_named(flatten, "some_str", NULL);

	// Validate content of variables
	ASSERT(!memcmp(test1->x, "abc", 3));
	ASSERT(!memcmp(test2->x, "def", 3));
	ASSERT(!memcmp(test3->x, "ghi", 3));
	ASSERT(!memcmp((*test4)[0].x, "zyx", 3));
	ASSERT(!memcmp((*test4)[1].x, "cvb", 3));
	ASSERT(!memcmp((*test4)[2].x, "sgh", 3));
	ASSERT(!memcmp(test5->x, "mij", 3));
	ASSERT(!strcmp(some_str, "te\0"));
	
	ASSERT_EQ(test1->value, 1);
	ASSERT_EQ(test2->value, 2);
	ASSERT_EQ(test3->value, 3);
	ASSERT_EQ((*test4)[0].value, 4);
	ASSERT_EQ((*test4)[1].value, 5);
	ASSERT_EQ((*test4)[2].value, 6);
	ASSERT_EQ(test5->value, 7);

	// Check whether the alignment of pointers have been preserved
	ASSERT_EQ((uintptr_t)test1 % 8, 0);
	ASSERT_EQ((uintptr_t)test2 % 8, 0);
	ASSERT_EQ((uintptr_t)test3 % 8, 0);
	ASSERT_EQ((uintptr_t)test4 % 8, 0);
	ASSERT_EQ((uintptr_t)test5 % 2, 0);
	ASSERT_EQ((uintptr_t)some_str % 8, 0);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("[UNIT] aligned_root_pointers", kflat_aligned_root_pointers_test, kflat_aligned_root_pointers_validate, KFLAT_TEST_ATOMIC | KFLAT_TEST_FORCE_CONTINOUS);

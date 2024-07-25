/**
 * @file unit_aligned_pointers.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct second_struct {
	unsigned long long data;
	char* test_string;
	unsigned long* test_numbers;
	int test_numbers_count;
};

struct alignment_structure {
	char* test_string;
	unsigned long long test_long;
	unsigned long* numbers;
	int numbers_count;
	struct second_struct* data;
};


/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(second_struct,
	AGGREGATE_FLATTEN_STRING(test_string);
	AGGREGATE_FLATTEN_TYPE_ARRAY(unsigned long, test_numbers, ATTR(test_numbers_count));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(alignment_structure,
	AGGREGATE_FLATTEN_STRING(test_string);
	AGGREGATE_FLATTEN_TYPE_ARRAY(unsigned long, numbers, ATTR(numbers_count));
	AGGREGATE_FLATTEN_STRUCT_ARRAY(second_struct, data, 1);
);

#define CHECK_ALLOC(SIZE)   ({void* addr = FLATTEN_BSP_ZALLOC(SIZE); if(addr == NULL) {ret = 1; goto exit;}; addr;})

static int unit_aligned_pointers_test(struct flat *flat) {
	int ret = 0;
	struct alignment_structure test1 = {0};

	FLATTEN_SETUP_TEST(flat);

	test1.test_string = CHECK_ALLOC(20);
	strcpy(test1.test_string, "an example string");

	test1.numbers_count = 20;
	test1.numbers = CHECK_ALLOC(test1.numbers_count * sizeof(unsigned long));
	for(int i = 0; i < test1.numbers_count; i++)
		test1.numbers[i] = i * 16;
	test1.test_long = 4096;

	test1.data = CHECK_ALLOC(sizeof(struct second_struct));
	test1.data->data = 12345;

	test1.data->test_string = CHECK_ALLOC(20);
	strcpy(test1.data->test_string, "a misc string");

	test1.data->test_numbers_count = 30;
	test1.data->test_numbers = CHECK_ALLOC(test1.data->test_numbers_count * sizeof(unsigned long));
	for(int i = 0; i < test1.data->test_numbers_count; i++)
		test1.data->test_numbers[i] = i * 16;


	FOR_EXTENDED_ROOT_POINTER(&test1, "test1", sizeof(test1),
		FLATTEN_STRUCT(alignment_structure, &test1);
	);

	ret = FLATTEN_FINISH_TEST(flat);

exit:
	FLATTEN_BSP_FREE(test1.data->test_string);
	FLATTEN_BSP_FREE(test1.data->test_numbers);
	FLATTEN_BSP_FREE(test1.data);
	FLATTEN_BSP_FREE(test1.numbers);
	FLATTEN_BSP_FREE(test1.test_string);
	return ret;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int unit_aligned_pointers_validate(void *memory, size_t size, CUnflatten flatten) {
	struct alignment_structure *test1 = (struct alignment_structure *)unflatten_root_pointer_named(flatten, "test1", NULL);

	// Validate content of variables
	ASSERT_EQ(test1->test_long, 4096);
	ASSERT_EQ(test1->numbers_count, 20);
	ASSERT(!strcmp(test1->test_string, "an example string"));
	for(int i = 0; i < test1->numbers_count; i++)
		ASSERT_EQ(test1->numbers[i], i * 16);

	ASSERT_EQ(test1->data->data, 12345);
	ASSERT_EQ(test1->data->test_numbers_count, 30);
	ASSERT(!strcmp(test1->data->test_string, "a misc string"));
	for(int i = 0; i < test1->data->test_numbers_count; i++)
		ASSERT_EQ(test1->data->test_numbers[i], i * 16);

	// Check whether the alignment of pointers have been preserved
	ASSERT_EQ((uintptr_t)test1 % 8, 0);
	ASSERT_EQ((uintptr_t)test1->numbers % 8, 0);
	ASSERT_EQ((uintptr_t)test1->test_string % 8, 0);
	ASSERT_EQ((uintptr_t)test1->data % 8, 0);
	ASSERT_EQ((uintptr_t)test1->data->test_string % 8, 0);
	ASSERT_EQ((uintptr_t)test1->data->test_numbers % 8, 0);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("[UNIT] aligned_pointers", unit_aligned_pointers_test, unit_aligned_pointers_validate, KFLAT_TEST_ATOMIC | KFLAT_TEST_FORCE_CONTINOUS);

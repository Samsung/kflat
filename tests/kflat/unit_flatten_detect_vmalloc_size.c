/**
 * @file unit_flatten_detect_vmalloc_size.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct flatten_detect_vmalloc_size_test {
	int detect_obj_supported;
	size_t stack_ptr_size_1;
	size_t stack_ptr_size_2;
	size_t global_ptr_size;

	int* heap_ptr_1;
	size_t heap_ptr_size_1;

	int* heap_ptr_2;
	size_t heap_ptr_size_2;

	int* heap_ptr_3;
	size_t heap_ptr_size_3;

	int* heap_ptr_4;
	size_t heap_ptr_size_4;

	int* vmalloc_ptr_1;
	size_t vmalloc_ptr_size_1;

	int* vmalloc_ptr_2;
	size_t vmalloc_ptr_size_2;

	size_t invalid_memory_size_1;
	size_t invalid_memory_size_2;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(flatten_detect_vmalloc_size_test,
	AGGREGATE_FLATTEN_TYPE_ARRAY(int, heap_ptr_1, AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(heap_ptr_1, 4) / 4);
	AGGREGATE_FLATTEN_TYPE_ARRAY(int, heap_ptr_2, AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(heap_ptr_2, 4) / 4);
	AGGREGATE_FLATTEN_TYPE_ARRAY(int, heap_ptr_3, AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(heap_ptr_3, 4) / 4);
	AGGREGATE_FLATTEN_TYPE_ARRAY(int, heap_ptr_4, AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(heap_ptr_4, 4) / 4);

	AGGREGATE_FLATTEN_TYPE_ARRAY(int, vmalloc_ptr_1, AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(vmalloc_ptr_1, 4) / 4);
	AGGREGATE_FLATTEN_TYPE_ARRAY(int, vmalloc_ptr_2, AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(vmalloc_ptr_2, 4) / 4);
);

#include <linux/vmalloc.h>

static int test_global[4];

static int kflat_flatten_detect_vmalloc_size_unit_test(struct flat *flat) {
	int err = 0;
	int stack_variable;
	char stack_string[8];
	struct flatten_detect_vmalloc_size_test test = {0};

	FLATTEN_SETUP_TEST(flat);
	test.detect_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);

	test.stack_ptr_size_1 = FLATTEN_DETECT_OBJECT_SIZE(&stack_variable, 0);
	test.stack_ptr_size_1 = FLATTEN_DETECT_OBJECT_SIZE(stack_string, 0);
	test.global_ptr_size = FLATTEN_DETECT_OBJECT_SIZE(test_global, 0);
	test.invalid_memory_size_1 = FLATTEN_DETECT_OBJECT_SIZE((void*) 0x0, 0);
	test.invalid_memory_size_2 = FLATTEN_DETECT_OBJECT_SIZE((void*) 0xffffff000000, 0);

	test.heap_ptr_1 = kmalloc(sizeof(int) * 32, GFP_KERNEL);
	if(test.heap_ptr_1 == NULL) {err = 1; goto out;}
	for(int i = 0; i < 32; i++)
		test.heap_ptr_1[i] = ((i + 0xff1) * 0xff313) % 87623451;

	test.heap_ptr_2 = kmalloc(sizeof(int) * 44, GFP_KERNEL);
	if(test.heap_ptr_2 == NULL) {err = 1; goto out;}
	for(int i = 0; i < 44; i++)
		test.heap_ptr_2[i] = ((i + 0x6123) * 0x88123) % 5248267;

	test.heap_ptr_3 = kmalloc(sizeof(int) * 256, GFP_KERNEL);
	if(test.heap_ptr_3 == NULL) {err = 1; goto out;}
	for(int i = 0; i < 256; i++)
		test.heap_ptr_3[i] = ((i + 0x213) * 0xaafc3) % 4447165;

	test.heap_ptr_4 = kmalloc(sizeof(int) * 200000, GFP_KERNEL);
	if(test.heap_ptr_4 == NULL) {err = 1; goto out;}
	for(int i = 0; i < 200000; i++)
		test.heap_ptr_4[i] = ((i + 0xfffa) * 0x587416) % 741325751;

	test.vmalloc_ptr_1 = vmalloc(sizeof(int) * 10000);
	if(test.vmalloc_ptr_1 == NULL) {err = 1; goto out;}
	for(int i = 0; i < 10000; i++)
		test.vmalloc_ptr_1[i] = ((i + 0x123) * 0x51231) % 12333121;

	test.vmalloc_ptr_2 = vmalloc(sizeof(int) * 4096);
	if(test.vmalloc_ptr_2 == NULL) {err = 1; goto out;}
	for(int i = 0; i < 4096; i++)
		test.vmalloc_ptr_2[i] = ((i + 0x11aad) * 0x514777d) % 52862171;

	test.heap_ptr_size_1 = FLATTEN_DETECT_OBJECT_SIZE(test.heap_ptr_1, 0);
	test.heap_ptr_size_2 = FLATTEN_DETECT_OBJECT_SIZE(test.heap_ptr_2, 0);
	test.heap_ptr_size_3 = FLATTEN_DETECT_OBJECT_SIZE(test.heap_ptr_3, 0);
	test.heap_ptr_size_4 = FLATTEN_DETECT_OBJECT_SIZE(test.heap_ptr_4, 0);
	test.vmalloc_ptr_size_1 = FLATTEN_DETECT_OBJECT_SIZE(test.vmalloc_ptr_1, 0);
	test.vmalloc_ptr_size_2 = FLATTEN_DETECT_OBJECT_SIZE(test.vmalloc_ptr_2, 0);

	FOR_ROOT_POINTER(&test,
		FLATTEN_STRUCT(flatten_detect_vmalloc_size_test, &test);
	);

out:
	kfree(test.heap_ptr_1);
	kfree(test.heap_ptr_2);
	kfree(test.heap_ptr_3);
	kfree(test.heap_ptr_4);
	vfree(test.vmalloc_ptr_1);
	vfree(test.vmalloc_ptr_2);

	return err;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_detect_vmalloc_size_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	
	struct flatten_detect_vmalloc_size_test *ptrs = (struct flatten_detect_vmalloc_size_test *)unflatten_root_pointer_seq(flatten, 0);

	if(!ptrs->detect_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	ASSERT_EQ(ptrs->stack_ptr_size_1, 0);
	ASSERT_EQ(ptrs->stack_ptr_size_2, 0);
	ASSERT_EQ(ptrs->invalid_memory_size_1, 0);
	ASSERT_EQ(ptrs->invalid_memory_size_2, 0);
	ASSERT_EQ(ptrs->global_ptr_size, 0);	// We can't detect global size for now

	ASSERT(ptrs->heap_ptr_size_1 >= 128 && ptrs->heap_ptr_size_1 <= 256);
	ASSERT(ptrs->heap_ptr_size_2 >= 176 && ptrs->heap_ptr_size_2 <= 256);
	ASSERT(ptrs->heap_ptr_size_3 >= 1024 && ptrs->heap_ptr_size_3 <= 2048);
	ASSERT(ptrs->heap_ptr_size_4 >= 800000 && ptrs->heap_ptr_size_4 <= 1048576);

	ASSERT(ptrs->vmalloc_ptr_size_1 >= 40000 && ptrs->vmalloc_ptr_size_1 <= 819200);
	ASSERT(ptrs->vmalloc_ptr_size_2 >= 16384 && ptrs->vmalloc_ptr_size_2 <= 32768);

	for(int i = 0; i < 32; i++)
		ASSERT_EQ(ptrs->heap_ptr_1[i],  ((i + 0xff1) * 0xff313) % 87623451);
	for(int i = 0; i < 44; i++)
		ASSERT_EQ(ptrs->heap_ptr_2[i], ((i + 0x6123) * 0x88123) % 5248267);
	for(int i = 0; i < 256; i++)
		ASSERT_EQ(ptrs->heap_ptr_3[i], ((i + 0x213) * 0xaafc3) % 4447165);
	for(int i = 0; i < 200000; i++)
		ASSERT_EQ(ptrs->heap_ptr_4[i], ((i + 0xfffa) * 0x587416) % 741325751);
	for(int i = 0; i < 10000; i++)
		ASSERT_EQ(ptrs->vmalloc_ptr_1[i], ((i + 0x123) * 0x51231) % 12333121);
	for(int i = 0; i < 4096; i++)
		ASSERT_EQ(ptrs->vmalloc_ptr_2[i], ((i + 0x11aad) * 0x514777d) % 52862171);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] flatten_detect_vmalloc_size", kflat_flatten_detect_vmalloc_size_unit_test, kflat_flatten_detect_vmalloc_size_unit_validate);

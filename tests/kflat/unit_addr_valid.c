/**
 * @file unit_addr_valid.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct addr_valid_result {
	bool test_null_pass;
	bool test_null_large_pass;
	bool test_zero_page_pass;
	bool test_user_ptr_pass;
	bool test_wild_ptr_pass;
	bool test_huge_size_pass;

	bool test_stack_addr_pass;
	bool test_global_addr_pass;
	bool test_heap_addr_pass;
	bool test_vmalloc_addr_pass;
	bool test_module_code_addr_pass;
	bool test_kernel_code_addr_pass;

	bool test_page_offset_pass;
	bool test_page_offset_2_pass;
	bool test_page_offset_3_pass;
	bool test_page_offset_4_pass;
	bool test_page_offset_5_pass;
};

/********************************/
#ifdef __TESTER__
/********************************/

#include <linux/vmalloc.h>

static int iarr[16];

FUNCTION_DEFINE_FLATTEN_STRUCT(addr_valid_result);

static int kflat_addr_valid_unit_test(struct flat *flat) {
	void *vmem, *kmem;
	struct addr_valid_result results = { 0 };

	FLATTEN_SETUP_TEST(flat);

	vmem = vmalloc(2 * PAGE_SIZE);
	kmem = kmalloc(30, GFP_KERNEL);
	if (!vmem || !kmem) {
		vfree(vmem);
		kfree(kmem);
		return -ENOMEM;
	}

	results.test_null_pass = !_addr_range_valid(NULL, 1);
	results.test_null_large_pass = !_addr_range_valid(NULL, PAGE_SIZE * 10);
	results.test_zero_page_pass = !_addr_range_valid((void *)0xFFF, PAGE_SIZE);
	results.test_user_ptr_pass = !_addr_range_valid((void *)0x8000200, 1) && !_addr_range_valid((void *)(1ULL << (46 - 1)), 1);
	results.test_wild_ptr_pass = !_addr_range_valid((void *)-1ULL, PAGE_SIZE);
	results.test_huge_size_pass = !_addr_range_valid(&results, PAGE_SIZE * 1024ULL * 1024 * 1024);

	results.test_stack_addr_pass = _addr_range_valid(&results, 1) &&
				       _addr_range_valid(&results, sizeof(results)) &&
				       _addr_range_valid(kflat, 1);
	results.test_global_addr_pass = _addr_range_valid(iarr, 1) && _addr_range_valid(iarr, sizeof(iarr));
	results.test_heap_addr_pass = _addr_range_valid(kmem, 30);
	results.test_vmalloc_addr_pass = _addr_range_valid(vmem, 2 * PAGE_SIZE);
	results.test_module_code_addr_pass = _addr_range_valid(kflat_addr_valid_unit_test, 10);
	results.test_kernel_code_addr_pass = _addr_range_valid(kfree, 10);

	results.test_page_offset_pass = _addr_range_valid(vmem + 2 * PAGE_SIZE - 1, 1);
	results.test_page_offset_2_pass = _addr_range_valid(vmem + PAGE_SIZE + 1, PAGE_SIZE - 1);
	results.test_page_offset_3_pass = _addr_range_valid(vmem + 1, 2 * PAGE_SIZE - 1);
	results.test_page_offset_4_pass = !_addr_range_valid(vmem - 1, 2 * PAGE_SIZE + 1);
	results.test_page_offset_5_pass = !_addr_range_valid(vmem + 2 * PAGE_SIZE, 1);

	vfree(vmem);
	kfree(kmem);

	// Send results back to user
	FOR_ROOT_POINTER(&results,
		FLATTEN_STRUCT(addr_valid_result, &results);
	);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_addr_valid_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct addr_valid_result *pResults = (struct addr_valid_result *)memory;

	ASSERT(pResults->test_null_pass);
	ASSERT(pResults->test_null_large_pass);
	ASSERT(pResults->test_zero_page_pass);
	ASSERT(pResults->test_user_ptr_pass);
	ASSERT(pResults->test_wild_ptr_pass);
	ASSERT(pResults->test_huge_size_pass);

	ASSERT(pResults->test_stack_addr_pass);
	ASSERT(pResults->test_global_addr_pass);
	ASSERT(pResults->test_heap_addr_pass);
	ASSERT(pResults->test_vmalloc_addr_pass);
	ASSERT(pResults->test_module_code_addr_pass);
	ASSERT(pResults->test_kernel_code_addr_pass);

	ASSERT(pResults->test_page_offset_pass);
	ASSERT(pResults->test_page_offset_2_pass);
	ASSERT(pResults->test_page_offset_3_pass);
	ASSERT(pResults->test_page_offset_4_pass);
	ASSERT(pResults->test_page_offset_5_pass);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] addr_valid", kflat_addr_valid_unit_test, kflat_addr_valid_unit_validate);

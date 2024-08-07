/**
 * @file unit_get_object.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct get_obj_result {
	bool get_obj_supported;

	bool test_kmalloc_200_pass;
	bool test_kmalloc_last_byte_pass;
	bool test_stack_pass;
	bool test_globals_pass;
	bool test_code_pass;
	bool test_vmalloc_pass;
	bool test_vmalloc_large_pass;
};

/********************************/
#ifdef __TESTER__
/********************************/

#include <linux/vmalloc.h>

#ifdef KFLAT_GET_OBJ_SUPPORT
static int iarr[16];
#endif


FUNCTION_DEFINE_FLATTEN_STRUCT(get_obj_result);

static int kflat_get_object_unit_test(struct flat *flat) {
	struct get_obj_result results = { 0 };

	FLATTEN_SETUP_TEST(flat);

#ifdef KFLAT_GET_OBJ_SUPPORT
	bool ret;
	void *start = NULL;
	void *end = NULL;
	void *buffer;

	results.get_obj_supported = true;

	// Look for 200 kmalloc object on heap
	buffer = kmalloc(200, GFP_KERNEL);
	ret = flatten_get_object(flat, buffer + 10, &start, &end);
	if (!ret) {
		flat_errs("get_object test: flatten_get_object failed to locate heap object");
	} else if (start != buffer || end >= buffer + 1024 || end < buffer + 200) {
		flat_errs("get_object test: flatten_get_object incorrectly located object 0x%llx:0x%llx (should be: 0x%llx:0x%llx)",
			  (uint64_t)start, (uint64_t)end, (uint64_t)buffer, (uint64_t)buffer + 200);
	} else
		results.test_kmalloc_200_pass = true;
	kfree(buffer);

	// Check NULL handling
	ret = flatten_get_object(flat, &ret, NULL, NULL);
	if (ret)
		flat_errs("get_object test: flatten_get_object accepted object from stack");
	else
		results.test_stack_pass = true;

	// Check globals handling
	ret = flatten_get_object(flat, &iarr, NULL, NULL);
	if (ret)
		flat_errs("get_object test: flatten_get_object accepted global object");
	else
		results.test_globals_pass = true;

	// Check code section handling
	ret = flatten_get_object(flat, kflat_get_object_unit_test, NULL, NULL);
	if (ret)
		flat_errs("get_object test: flatten_get_object accepted pointer to code section");
	else
		results.test_code_pass = true;

	// Check vmalloc memory
	buffer = vmalloc(PAGE_SIZE);
	ret = flatten_get_object(flat, buffer, &start, &end);
	if (!ret)
		flat_errs("get_object test: flatten_get_object ignored pointer to vmalloc area");
	else
		results.test_vmalloc_pass = true;
	vfree(buffer);

	buffer = vmalloc(12 * PAGE_SIZE);
	ret = flatten_get_object(flat, buffer + PAGE_SIZE * 2 + 1, &start, &end);
	if (!ret)
		flat_errs("get_object test: flatten_get_object ignored pointer to vmalloc area");
	else if(start != buffer || end != buffer + 12 * PAGE_SIZE - 1)
		flat_errs("get_object test: flatten_get_object incorrectly located vmalloc(PAGE_SIZE * 12) memory - s:%llx; e:%llx",
					(uint64_t) start, (uint64_t) end);
	else
		results.test_vmalloc_large_pass = true;
	vfree(buffer);

	// Check access to the last byte of allocated memory
	buffer = kmalloc(17, GFP_KERNEL);
	ret = flatten_get_object(flat, buffer + 16, &start, &end);
	if (!ret)
		flat_errs("get_object test: flatten_get_object failed to locate heap(17) object");
	else if (start != buffer || end >= buffer + 256 || end < buffer + 17)
		flat_errs("get_object test: flatten_get_object incorrectly located object 0x%llx:0x%llx (should be 0x%llx:0x%llx",
			  (uint64_t)start, (uint64_t)end, (uint64_t)buffer, (uint64_t)buffer + 17);
	else
		results.test_kmalloc_last_byte_pass = true;
	kfree(buffer);

#endif

	// Send results back to user
	FOR_ROOT_POINTER(&results,
		FLATTEN_STRUCT(get_obj_result, &results);
	);

	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_get_object_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct get_obj_result *pResults = (struct get_obj_result *)memory;

	if (!pResults->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	ASSERT(pResults->test_kmalloc_200_pass);
	ASSERT(pResults->test_kmalloc_last_byte_pass);
	ASSERT(pResults->test_stack_pass);
	ASSERT(pResults->test_globals_pass);
	ASSERT(pResults->test_code_pass);
	ASSERT(pResults->test_vmalloc_pass);
	ASSERT(pResults->test_vmalloc_large_pass);
	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] get_object", kflat_get_object_unit_test, kflat_get_object_unit_validate);

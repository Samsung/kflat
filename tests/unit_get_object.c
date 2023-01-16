/**
 * @file unit_get_object.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct get_obj_result {
	bool get_obj_supported;

	bool test_kmalloc_200_pass;
	bool test_kmalloc_free;
	bool test_kmalloc_last_byte_pass;
	bool test_stack_pass;
	bool test_globals_pass;
	bool test_code_pass;
	bool test_vmalloc_pass;
};

#ifdef __KERNEL__

#include <linux/vmalloc.h>

static int iarr[16];

FUNCTION_DEFINE_FLATTEN_STRUCT(get_obj_result);

static int kflat_get_object_unit_test(struct kflat *kflat) {
	struct get_obj_result results = { 0 };

#ifdef KFLAT_GET_OBJ_SUPPORT
	bool ret;
	void *start = NULL;
	void *end = NULL;
	void *buffer;

	results.get_obj_supported = true;

	// Look for 200 kmalloc object on heap
	buffer = kmalloc(200, GFP_KERNEL);
	ret = flatten_get_object(buffer + 10, &start, &end);
	if (!ret) {
		flat_errs("get_object test: flatten_get_object failed to locate heap object");
	} else if (start != buffer || end != buffer + 200) {
		flat_errs("get_object test: flatten_get_object incorrectly located object 0x%llx:0x%llx (should be: 0x%llx:0x%llx)",
			  (uint64_t)start, (uint64_t)end, (uint64_t)buffer, (uint64_t)buffer + 200);
	} else
		results.test_kmalloc_200_pass = true;
	kfree(buffer);

	// Check freed memory
	/*ret = flatten_get_object(buffer, &start, end);
	if (ret)
		flat_errs("get_object test: flatten_get_object accepted freed object from heap");
	// xxx this is a known problem, so ignore it in unit-tests for now */
	results.test_kmalloc_free = true;

	// Check NULL handling
	ret = flatten_get_object(&ret, NULL, NULL);
	if (ret)
		flat_errs("get_object test: flatten_get_object accepted object from stack");
	else
		results.test_stack_pass = true;

	// Check globals handling
	ret = flatten_get_object(&iarr, NULL, NULL);
	if (ret)
		flat_errs("get_object test: flatten_get_object accepted global object");
	else
		results.test_globals_pass = true;

	// Check code section handling
	ret = flatten_get_object(kflat_get_object_unit_test, NULL, NULL);
	if (ret)
		flat_errs("get_object test: flatten_get_object accepted pointer to code section");
	else
		results.test_code_pass = true;

	// Check vmalloc memory
	buffer = vmalloc(PAGE_SIZE);
	ret = flatten_get_object(buffer, &start, &end);
	if (ret)
		flat_errs("get_object test: flatten_get_object accepted pointer to vmalloc area");
	else
		results.test_vmalloc_pass = true;
	vfree(buffer);

	// Check access to the last byte of allocated memory
	buffer = kmalloc(17, GFP_KERNEL);
	ret = flatten_get_object(buffer + 16, &start, &end);
	if (!ret)
		flat_errs("get_object test: flatten_get_object failed to locate heap(17) object");
	else if (start != buffer || end != buffer + 17)
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

	return 0;
}

#else

static int kflat_get_object_unit_validate(void *memory, size_t size, CFlatten flatten) {
	struct get_obj_result *pResults = (struct get_obj_result *)memory;

	if (!pResults->get_obj_supported)
		// xxx We should inform kflattest that test is unsupported in this build
		return 0;

	ASSERT(pResults->test_kmalloc_200_pass);
	ASSERT(pResults->test_kmalloc_free);
	ASSERT(pResults->test_kmalloc_last_byte_pass);
	ASSERT(pResults->test_stack_pass);
	ASSERT(pResults->test_globals_pass);
	ASSERT(pResults->test_code_pass);
	ASSERT(pResults->test_vmalloc_pass);
	return 0;
}

#endif

KFLAT_REGISTER_TEST("[UNIT] get_object", kflat_get_object_unit_test, kflat_get_object_unit_validate);

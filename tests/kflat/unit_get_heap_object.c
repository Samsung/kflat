/**
 * @file unit_get_heap_object.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct {
    size_t alloc_size;
    size_t min_result;
    size_t max_result;
    size_t test_offset;
} test_sizes[] = {
    /* size */  /* min */   /* max */   /* off */
    /* kmalloc */
    {10,        16,         64,         5},
    {64,        64,         64,         10},
    {90,        64,         128,        15},
    {128,       128,        128,        22},
    {256,       256,        256,        22},
    {2048,      2048,       2048,       22},
    {4096,      4096,       4096,       22},
    {8192,      8192,       8192,       22},

    /* kmalloc_large */
    {9000,      9000,       16384,      0},
    {9000,      9000,       16384,      16},
    {9000,      9000,       16384,      4097},
    {9000,      9000,       16384,      8999},
    {10000,     10000,      16384,      10},
    {30000,     30000,      32768,      10},
    {60000,     60000,      65536,      10},
};

struct get_heap_obj_result {
	bool get_obj_supported;
    bool test_results[sizeof(test_sizes) / sizeof(test_sizes[0])];
};

/********************************/
#ifdef __TESTER__
/********************************/

#include <linux/vmalloc.h>

FUNCTION_DEFINE_FLATTEN_STRUCT(get_heap_obj_result);

#ifdef KFLAT_GET_OBJ_SUPPORT
static bool test_kmalloc_size(struct flat *flat, size_t size, size_t min, size_t max, off_t off) {
    bool ret, result = false;
	void *start = NULL;
	void *end = NULL;
	void *buffer;
    
    buffer = kmalloc(size, GFP_KERNEL);
	ret = flatten_get_object(flat, buffer + off, &start, &end);
	if (!ret)
		flat_errs("get_object test: flatten_get_object failed to locate heap object of size %lu", size);
	else if (start != buffer || end > buffer + max - 1 || end < buffer + min - 1)
		flat_errs("get_object test: flatten_get_object incorrectly located object 0x%llx:0x%llx (should be: 0x%llx:[0x%llx-0x%llx])",
			  (uint64_t)start, (uint64_t)end, (uint64_t)buffer, (uint64_t)buffer + min, (uint64_t)buffer + max);
	else
		result = true;

	kfree(buffer);
    return result;
}
#endif

static int kflat_get_heap_object_unit_test(struct flat *flat) {
	struct get_heap_obj_result results = { 0 };

	FLATTEN_SETUP_TEST(flat);

#ifdef KFLAT_GET_OBJ_SUPPORT
	results.get_obj_supported = true;
    for(size_t i = 0; i < sizeof(test_sizes) / sizeof(test_sizes[0]); i++)
        results.test_results[i] = test_kmalloc_size(flat,
                                    test_sizes[i].alloc_size, 
                                    test_sizes[i].min_result, 
                                    test_sizes[i].max_result, 
                                    test_sizes[i].test_offset);
#endif

	// Send results back to user
	FOR_ROOT_POINTER(&results,
		FLATTEN_STRUCT(get_heap_obj_result, &results);
	);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_get_heap_object_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct get_heap_obj_result *pResults = (struct get_heap_obj_result *)memory;

	if (!pResults->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

    for(size_t i = 0; i < sizeof(test_sizes) / sizeof(test_sizes[0]); i++) {
        if(!pResults->test_results[i]) {
            printf("\tHeap test #%zu failed (size:%zu)\n", i, test_sizes[i].alloc_size);
        }
        ASSERT(pResults->test_results[i]);
    }
	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] get_heap_object", kflat_get_heap_object_unit_test, kflat_get_heap_object_unit_validate);

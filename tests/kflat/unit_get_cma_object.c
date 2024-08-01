/**
 * @file unit_get_cma_object.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct get_cma_obj_result {
	bool get_obj_supported;

    bool stack_pointer;
    bool invalid_pointer;
    bool heap_pointer;
    bool cma_pointer;
    bool end_of_cma_area;
    bool middle_of_cma_area;
};

/********************************/
#ifdef __TESTER__
/********************************/

#if defined(KFLAT_GET_OBJ_SUPPORT) && defined(CONFIG_CMA)
#include <linux/cma.h>
#ifdef CONFIG_X86_64
#include <asm/io.h>
#endif

static struct cma* some_cma;
static int _cma_areas_it(struct cma* cma, void* data) {
    some_cma = cma;
    return 1;
}
#endif

FUNCTION_DEFINE_FLATTEN_STRUCT(get_cma_obj_result);

static int kflat_get_cma_object_unit_test(struct flat *flat) {
	struct get_cma_obj_result results = { 0 };

	FLATTEN_SETUP_TEST(flat);

#if defined(KFLAT_GET_OBJ_SUPPORT) && defined(CONFIG_CMA)
    // For test allocate 8 pages from CMA allocator
    void* cma_memory;
    void* heap_ptr;
    struct page* area;

    cma_for_each_area(_cma_areas_it, NULL);
    area = cma_alloc(some_cma, 8, 0, true);
    if(area == NULL)
        return 1;
    cma_memory = phys_to_virt(page_to_phys(area));

    heap_ptr = kmalloc(128, GFP_KERNEL);

	results.get_obj_supported = true;
    results.stack_pointer = is_cma_memory(&results) == false;
    results.invalid_pointer = is_cma_memory((void*) 0xc0ffee00aabb) == false;
    results.heap_pointer = is_cma_memory(heap_ptr) == false;
    
    results.cma_pointer = is_cma_memory(cma_memory) == true;
    results.end_of_cma_area = is_cma_memory(cma_memory + 8 * PAGE_SIZE - 10) == true;
    results.middle_of_cma_area = is_cma_memory(cma_memory + 4 * PAGE_SIZE) == true;

    // Release CMA memory
    cma_release(some_cma, area, 8);

    kfree(heap_ptr);
#endif

	// Send results back to user
	FOR_ROOT_POINTER(&results,
		FLATTEN_STRUCT(get_cma_obj_result, &results);
	);

	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_get_cma_object_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct get_cma_obj_result *pResults = (struct get_cma_obj_result *)memory;

	if (!pResults->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

    ASSERT(pResults->stack_pointer);
    ASSERT(pResults->invalid_pointer);
    ASSERT(pResults->heap_pointer);

    ASSERT(pResults->cma_pointer);
    ASSERT(pResults->end_of_cma_area);
    ASSERT(pResults->middle_of_cma_area);
	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] get_cma_object", kflat_get_cma_object_unit_test, kflat_get_cma_object_unit_validate);

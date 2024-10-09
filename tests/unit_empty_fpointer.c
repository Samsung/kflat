/**
 * @file unit_empty_fpointer.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

// Common structure types
struct fptrmap_test_struct {
	int* ints_array;
    size_t array_size;
};


/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(fptrmap_test_struct,
	AGGREGATE_FLATTEN_TYPE_ARRAY(int, ints_array, ATTR(array_size));
);

static int kflat_empty_fptrmap_test(struct flat *flat) {
    int array[5] = {0, 1, 2, 3, 4};
	struct fptrmap_test_struct test = {
        .ints_array = array,
        .array_size = 5
    };

	FLATTEN_SETUP_TEST(flat);
	FOR_ROOT_POINTER(&test,
		FLATTEN_STRUCT(fptrmap_test_struct, &test);
	);
	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/


static uintptr_t empty_gfa(const char *fsym) {
	return (uintptr_t)NULL;
}

static int kflat_frpmap_test_validate(void *memory, size_t size, CUnflatten flatten) {
	struct fptrmap_test_struct *fptrmap = (struct fptrmap_test_struct *)unflatten_root_pointer_seq(flatten, 0);
    
    ASSERT_EQ(fptrmap->array_size, 5);
    for(int i = 0; i < fptrmap->array_size; i++)
        ASSERT_EQ(fptrmap->ints_array[i], i);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_GFA_FLAGS("[UNIT] empty_fptrmap", kflat_empty_fptrmap_test, kflat_frpmap_test_validate, empty_gfa, KFLAT_TEST_ATOMIC);

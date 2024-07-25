/**
 * @file unit_flatten_detect_objsize_self_contained.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct mere_pointers_sc {
	int detect_obj_supported;
	void* a;
	void* b;
	void* c;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(mere_pointers_sc,
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(unsigned char,a,offsetof(struct mere_pointers_sc,a),AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(a,offsetof(struct mere_pointers_sc,a)));
	/* This will fail to detect objects size and will copy 8 bytes */
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(unsigned char,b,offsetof(struct mere_pointers_sc,b),AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(b,offsetof(struct mere_pointers_sc,b),8));
	/* This will fail to detect objects size and will copy 1 byte */
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(unsigned char,c,offsetof(struct mere_pointers_sc,c),AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE_SELF_CONTAINED(c,offsetof(struct mere_pointers_sc,c)));
);

#include <linux/vmalloc.h>

char gcarr_sc[4] = "ABCD";

static int kflat_flatten_detect_objsize_self_contained_unit_test(struct flat *flat) {

	struct mere_pointers_sc ptrs = {};
	unsigned long stack_long = 0xD0D0CACA;

	FLATTEN_SETUP_TEST(flat);

#ifndef KFLAT_GET_OBJ_SUPPORT
	ptrs.detect_obj_supported = false;
#else
	ptrs.detect_obj_supported = true;
#endif

	ptrs.a = kmalloc(40, GFP_KERNEL);
	for (int i=0; i<40; ++i) {
		((unsigned char*)ptrs.a)[i] = 3*i;
	}
	ptrs.b = &stack_long;
	ptrs.c = gcarr_sc;

	FOR_ROOT_POINTER(&ptrs,
		FLATTEN_STRUCT_SELF_CONTAINED(mere_pointers_sc, sizeof(struct mere_pointers_sc), &ptrs);
	);

	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_detect_objsize_self_contained_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	
	struct mere_pointers_sc *ptrs = (struct mere_pointers_sc *)unflatten_root_pointer_seq(flatten, 0);

	if(!ptrs->detect_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	for (int i=0; i<40; ++i) {
		ASSERT_EQ(((unsigned char*)ptrs->a)[i],3*i);
	}
	ASSERT_EQ(*((unsigned long*)ptrs->b),0xD0D0CACA);
	ASSERT_EQ(*((unsigned char*)ptrs->c),'A');

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] flatten_detect_objsize_self_contained", kflat_flatten_detect_objsize_self_contained_unit_test, kflat_flatten_detect_objsize_self_contained_unit_validate);

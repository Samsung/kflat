/**
 * @file unit_flatten_detect_objsize.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct mere_pointers {
	void* a;
	void* b;
	void* c;
};

#ifdef __KERNEL__

FUNCTION_DEFINE_FLATTEN_STRUCT(mere_pointers,
	AGGREGATE_FLATTEN_TYPE_ARRAY(unsigned char,a,AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(a));
	/* This will fail to detect objects size and will copy 8 bytes */
	AGGREGATE_FLATTEN_TYPE_ARRAY(unsigned char,b,AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(b,8));
	/* This will fail to detect objects size and will copy 1 byte */
	AGGREGATE_FLATTEN_TYPE_ARRAY(unsigned char,c,AGGREGATE_FLATTEN_DETECT_OBJECT_SIZE(c));
);

#include <linux/vmalloc.h>

char gcarr[4] = "ABCD";

static int kflat_flatten_detect_objsize_unit_test(struct kflat *kflat) {

	struct mere_pointers ptrs = {};
	unsigned long stack_long = 0xD0D0CACA;

	ptrs.a = kmalloc(40, GFP_KERNEL);
	for (int i=0; i<40; ++i) {
		((unsigned char*)ptrs.a)[i] = 3*i;
	}
	ptrs.b = &stack_long;
	ptrs.c = gcarr;

	FOR_ROOT_POINTER(&ptrs,
		FLATTEN_STRUCT(mere_pointers, &ptrs);
	);

	return 0;
}

#else

static int kflat_flatten_detect_objsize_unit_validate(void *memory, size_t size, CFlatten flatten) {
	
	struct mere_pointers *ptrs = (struct mere_pointers *)flatten_root_pointer_seq(flatten, 0);

	for (int i=0; i<40; ++i) {
		ASSERT_EQ(((unsigned char*)ptrs->a)[i],3*i);
	}
	ASSERT_EQ(*((unsigned long*)ptrs->b),0xD0D0CACA);
	ASSERT_EQ(*((unsigned char*)ptrs->c),'A');

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST("[UNIT] flatten_detect_objsize", kflat_flatten_detect_objsize_unit_test, kflat_flatten_detect_objsize_unit_validate);

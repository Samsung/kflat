/**
 * @file example_flexible.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct flex_B {
	int field;
};
struct flex_A {
	int get_obj_supported;
	size_t cnt;
	struct flex_B arr[0];
};

struct flex_C {
	long l;
	const char* name;
	unsigned long arr[0];
};

#ifdef __KERNEL__

FUNCTION_DEFINE_FLATTEN_STRUCT(flex_B);
FUNCTION_DEFINE_FLATTEN_STRUCT(flex_A,
	AGGREGATE_FLATTEN_STRUCT_FLEXIBLE(flex_B, arr);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(flex_C,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_TYPE_ARRAY_FLEXIBLE(unsigned long, arr);
);

static int kflat_flexible_test(struct kflat *kflat) {
	struct flex_A *a = kmalloc(sizeof(struct flex_A) + 3 * sizeof(struct flex_B), GFP_KERNEL);
	a->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	a->cnt = 3;
	a->arr[0].field = 1;
	a->arr[1].field = 0xaaddcc;
	a->arr[2].field = 0xcafecafe;

	struct flex_C *c = kmalloc(sizeof(struct flex_C) + 10 * sizeof(unsigned long), GFP_KERNEL);
	c->l = 0xBEEFBEEF;
	c->name = "Flexible array of longs";
	for (int i=0; i<10; ++i) {
		c->arr[i] = ((c->l + 888*i) >> 4)% 16;
	}

	FOR_ROOT_POINTER(a,
		FLATTEN_STRUCT(flex_A, a);
    );

    FOR_ROOT_POINTER(c,
		FLATTEN_STRUCT(flex_C, c);
    );

	kfree(a);
	kfree(c);
	return 0;
}

#else

static int kflat_flexible_validate(void *memory, size_t size, CFlatten flatten) {
	struct flex_A *pA = (struct flex_A*)flatten_root_pointer_seq(flatten, 0);
	struct flex_C *pC = (struct flex_C*)flatten_root_pointer_seq(flatten, 1);
	
	if(!pA->get_obj_supported)
		return KFLAT_TEST_UNSUPPORTED;

	ASSERT(pA->cnt == 3);
	ASSERT(pA->arr[0].field == 1);
	ASSERT(pA->arr[1].field == 0xaaddcc);
	ASSERT(pA->arr[2].field == 0xcafecafe);

	ASSERT_EQ(pC->l,0xBEEFBEEF);
	ASSERT(!strcmp(pC->name,"Flexible array of longs"));
	for (int i=0; i<10; ++i) {
		ASSERT_EQ(pC->arr[i],((pC->l + 888*i) >> 4)% 16);
	}

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST("FLEXIBLE", kflat_flexible_test, kflat_flexible_validate);

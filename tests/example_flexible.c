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
	size_t cnt;
	struct flex_B arr[0];
};

#ifdef __KERNEL__

FUNCTION_DEFINE_FLATTEN_STRUCT(flex_B);
FUNCTION_DEFINE_FLATTEN_STRUCT(flex_A,
	AGGREGATE_FLATTEN_STRUCT_FLEXIBLE(flex_B, arr);
);

static int kflat_flexible_test(struct kflat *kflat) {
	struct flex_A *a = kmalloc(sizeof(struct flex_A) + 3 * sizeof(struct flex_B), GFP_KERNEL);
	a->cnt = 3;
	a->arr[0].field = 1;
	a->arr[1].field = 0xaaddcc;
	a->arr[2].field = 0xcafecafe;

	FOR_ROOT_POINTER(a,
		FLATTEN_STRUCT(flex_A, a);
    );

	kfree(a);
	return 0;
}

#else

static int kflat_flexible_validate(void *memory, size_t size, CFlatten flatten) {
	struct flex_A *pA = (struct flex_A *)memory;
	ASSERT(pA->cnt == 3);
	ASSERT(pA->arr[0].field == 1);
	ASSERT(pA->arr[1].field == 0xaaddcc);
	ASSERT(pA->arr[2].field == 0xcafecafe);
	return 0;
}

#endif

KFLAT_REGISTER_TEST("FLEXIBLE", kflat_flexible_test, kflat_flexible_validate);

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

typedef struct {
	int field;
} flex_D;

struct flex_E {
	size_t cnt;
	flex_D arr[0];
};

union flex_F {
	int field;
};

struct flex_G {
	size_t cnt;
	union flex_F arr[0];
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

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(flex_D);
FUNCTION_DEFINE_FLATTEN_STRUCT(flex_E,
	AGGREGATE_FLATTEN_STRUCT_TYPE_FLEXIBLE(flex_D, arr);
);

FUNCTION_DEFINE_FLATTEN_UNION(flex_F);
FUNCTION_DEFINE_FLATTEN_STRUCT(flex_G,
	AGGREGATE_FLATTEN_UNION_FLEXIBLE(flex_F, arr);
);

static int kflat_flexible_test(struct kflat *kflat) {
	struct flex_A *a;
	struct flex_C *c;
	struct flex_E *e;
	struct flex_G *g;

	a = kmalloc(sizeof(struct flex_A) + 3 * sizeof(struct flex_B), GFP_KERNEL);
	a->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	a->cnt = 3;
	a->arr[0].field = 1;
	a->arr[1].field = 0xaaddcc;
	a->arr[2].field = 0xcafecafe;

	c = kmalloc(sizeof(struct flex_C) + 10 * sizeof(unsigned long), GFP_KERNEL);
	c->l = 0xBEEFBEEF;
	c->name = "Flexible array of longs";
	for (int i=0; i<10; ++i) {
		c->arr[i] = ((c->l + 888*i) >> 4)% 16;
	}

	e = kmalloc(sizeof(struct flex_E) + 3 * sizeof(flex_D), GFP_KERNEL);
	e->cnt = 3;
	e->arr[0].field = 2;
	e->arr[1].field = 0xcceeff;
	e->arr[2].field = 0xba5eba11;

	g = kmalloc(sizeof(struct flex_G) + 3 * sizeof(union flex_F), GFP_KERNEL);
	g->cnt = 3;
	g->arr[0].field = 3;
	g->arr[1].field = 0xddeeaa;
	g->arr[2].field = 0xf01dab1e;

	FOR_ROOT_POINTER(a,
		FLATTEN_STRUCT(flex_A, a);
    );

    FOR_ROOT_POINTER(c,
		FLATTEN_STRUCT(flex_C, c);
    );

    FOR_ROOT_POINTER(e,
		FLATTEN_STRUCT(flex_E, e);
    );

    FOR_ROOT_POINTER(g,
		FLATTEN_STRUCT(flex_G, g);
    );

	kfree(a);
	kfree(c);
	kfree(e);
	kfree(g);
	return 0;
}

#else

static int kflat_flexible_validate(void *memory, size_t size, CFlatten flatten) {
	struct flex_A *pA = (struct flex_A*)flatten_root_pointer_seq(flatten, 0);
	struct flex_C *pC = (struct flex_C*)flatten_root_pointer_seq(flatten, 1);
	struct flex_E *pE = (struct flex_E*)flatten_root_pointer_seq(flatten, 2);
	struct flex_G *pG = (struct flex_G*)flatten_root_pointer_seq(flatten, 3);
	
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

	ASSERT(pE->cnt == 3);
	ASSERT(pE->arr[0].field == 2);
	ASSERT(pE->arr[1].field == 0xcceeff);
	ASSERT(pE->arr[2].field == 0xba5eba11);

	ASSERT(pG->cnt == 3);
	ASSERT(pG->arr[0].field == 3);
	ASSERT(pG->arr[1].field == 0xddeeaa);
	ASSERT(pG->arr[2].field == 0xf01dab1e);

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST("FLEXIBLE", kflat_flexible_test, kflat_flexible_validate);

/**
 * @file example_flexible_self_contained.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 *
 */

/*
--AGGREGATE_FLATTEN_UNION_FLEXIBLE_SELF_CONTAINED
*/

#include "common.h"

struct flexsc_B {
	int field;
};

struct flexsc_A {
	int get_obj_supported;
	size_t cnt;
	struct flexsc_B arr[0];
};

struct flexsc_C {
	long l;
	const char* name;
	unsigned long arr[0];
};

typedef struct {
	int field;
} flexsc_D;

struct flexsc_E {
	size_t cnt;
	flexsc_D arr[0];
};

union flexsc_F {
	int field;
};

struct flexsc_G {
	size_t cnt;
	union flexsc_F arr[0];
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(flexsc_B);
FUNCTION_DEFINE_FLATTEN_STRUCT_FLEXIBLE(flexsc_A,
	AGGREGATE_FLATTEN_STRUCT_FLEXIBLE_SELF_CONTAINED(flexsc_B, sizeof(struct flexsc_B), arr, offsetof(struct flexsc_A,arr));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_FLEXIBLE(flexsc_C,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_TYPE_ARRAY_FLEXIBLE_SELF_CONTAINED(unsigned long, arr, offsetof(struct flexsc_C,arr));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE_FLEXIBLE(flexsc_D);
FUNCTION_DEFINE_FLATTEN_STRUCT(flexsc_E,
	AGGREGATE_FLATTEN_STRUCT_TYPE_FLEXIBLE_SELF_CONTAINED(flexsc_D, sizeof(flexsc_D), arr, offsetof(struct flexsc_E,arr));
);

FUNCTION_DEFINE_FLATTEN_UNION(flexsc_F);
FUNCTION_DEFINE_FLATTEN_STRUCT_FLEXIBLE(flexsc_G,
	AGGREGATE_FLATTEN_UNION_FLEXIBLE_SELF_CONTAINED(flexsc_F, sizeof(union flexsc_F), arr, offsetof(struct flexsc_G,arr));
);

static int kflat_flexible_self_contained_test(struct flat *flat) {
	int get_obj_supported;
	struct flexsc_A *a;
	struct flexsc_C *c;
	struct flexsc_E *e;
	struct flexsc_G *g;

	FLATTEN_SETUP_TEST(flat);
	get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);

	a = kmalloc(sizeof(struct flexsc_A) + 3 * sizeof(struct flexsc_B), GFP_KERNEL);
	a->get_obj_supported = IS_ENABLED(KFLAT_GET_OBJ_SUPPORT);
	a->cnt = 3;
	a->arr[0].field = 1;
	a->arr[1].field = 0xaaddcc;
	a->arr[2].field = 0xcafecafe;

	c = kmalloc(sizeof(struct flexsc_C) + 10 * sizeof(unsigned long), GFP_KERNEL);
	c->l = 0xBEEFBEEF;
	c->name = "Flexible array of longs";
	for (int i=0; i<10; ++i) {
		c->arr[i] = ((c->l + 888*i) >> 4)% 16;
	}

	e = kmalloc(sizeof(struct flexsc_E) + 3 * sizeof(flexsc_D), GFP_KERNEL);
	e->cnt = 3;
	e->arr[0].field = 2;
	e->arr[1].field = 0xcceeff;
	e->arr[2].field = 0xba5eba11;

	g = kmalloc(sizeof(struct flexsc_G) + 3 * sizeof(union flexsc_F), GFP_KERNEL);
	g->cnt = 3;
	g->arr[0].field = 3;
	g->arr[1].field = 0xddeeaa;
	g->arr[2].field = 0xf01dab1e;

	FOR_ROOT_POINTER(&get_obj_supported,
		FLATTEN_TYPE(int, &get_obj_supported);
	);

#ifdef KFLAT_GET_OBJ_SUPPORT
	FOR_ROOT_POINTER(a,
		FLATTEN_STRUCT(flexsc_A, a);
	);

	FOR_ROOT_POINTER(c,
		FLATTEN_STRUCT(flexsc_C, c);
	);

	FOR_ROOT_POINTER(e,
		FLATTEN_STRUCT(flexsc_E, e);
	);

	FOR_ROOT_POINTER(g,
		FLATTEN_STRUCT(flexsc_G, g);
	);
#endif

	kfree(a);
	kfree(c);
	kfree(e);
	kfree(g);
	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flexible_self_contained_validate(void *memory, size_t size, CUnflatten flatten) {
	int* get_obj_supported = (int*) unflatten_root_pointer_seq(flatten, 0);
	struct flexsc_A *pA;
	struct flexsc_C *pC;
	struct flexsc_E *pE;
	struct flexsc_G *pG;
	
	if(get_obj_supported == NULL || *get_obj_supported == false)
		return KFLAT_TEST_UNSUPPORTED;

	pA = (struct flexsc_A*)unflatten_root_pointer_seq(flatten, 1);
	pC = (struct flexsc_C*)unflatten_root_pointer_seq(flatten, 2);
	pE = (struct flexsc_E*)unflatten_root_pointer_seq(flatten, 3);
	pG = (struct flexsc_G*)unflatten_root_pointer_seq(flatten, 4);

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

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("FLEXIBLE_SELF_CONTAINED", kflat_flexible_self_contained_test, kflat_flexible_self_contained_validate);

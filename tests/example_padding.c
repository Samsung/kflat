/**
 * @file example_padding.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct paddingA {
	int i;
};

struct paddingB {
	char c;
} __attribute__((aligned(sizeof(long))));

struct paddingC {
	char c;
};

struct paddingRoot {
	struct paddingA *a0;
	struct paddingB *b;
	struct paddingA *a1;
	struct paddingC *c;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(paddingA);
FUNCTION_DEFINE_FLATTEN_STRUCT(paddingB,
	STRUCT_ALIGN(sizeof(long));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(paddingC);
FUNCTION_DEFINE_FLATTEN_STRUCT(paddingRoot,
	AGGREGATE_FLATTEN_STRUCT(paddingA, a0);
	AGGREGATE_FLATTEN_STRUCT(paddingB, b);
	AGGREGATE_FLATTEN_STRUCT(paddingA, a1);
	AGGREGATE_FLATTEN_STRUCT(paddingC, c);
);

static int kflat_padding_test(struct flat *flat) {
	struct paddingA a0 = { 3 };
	struct paddingB b = { '3' };
	struct paddingA a1 = { 33 };
	struct paddingC c = { 'x' };

	struct paddingRoot r = { &a0, &b, &a1, &c };

	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(&r,
		FLATTEN_STRUCT(paddingRoot, &r);
	);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_padding_validate(void *memory, size_t size, CUnflatten flatten) {
	struct paddingRoot *r = (struct paddingRoot *)memory;
	ASSERT(r->a0->i == 3);
	ASSERT(r->b->c == '3');
	ASSERT(r->a1->i == 33);
	ASSERT(r->c->c == 'x');

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("PADDING", kflat_padding_test, kflat_padding_validate, KFLAT_TEST_ATOMIC);

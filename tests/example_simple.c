/**
 * @file simple.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct B {
	unsigned char T[4];
};
struct A {
	unsigned long X;
	struct B *pB;
};

#ifdef __KERNEL__

FUNCTION_DECLARE_FLATTEN_STRUCT(B);
FUNCTION_DECLARE_FLATTEN_STRUCT(A);

FUNCTION_DEFINE_FLATTEN_STRUCT(B);
FUNCTION_DEFINE_FLATTEN_STRUCT(A,
	AGGREGATE_FLATTEN_STRUCT(B, pB);
);

static int kflat_simple_test(struct kflat *kflat) {
	struct B b = { "ABC" };
	struct A a = { 0x0000404F, &b };
	struct A *pA = &a;
	struct A *vpA = (struct A *)0xdeadbeefdabbad00;

	FOR_ROOT_POINTER(pA,
		FLATTEN_STRUCT(A, vpA);
		FLATTEN_STRUCT(A, pA);
	);

	return 0;
}

#else

static int kflat_simple_validate(void *memory, size_t size, CUnflatten flatten) {
	struct A *pA = (struct A *)memory;

	ASSERT(pA->X == 0x0000404F);
	ASSERT(!strcmp((const char *)pA->pB->T, "ABC"));
	
	PRINT("struct A = {.X = 0x%08lx, .pB = \"%s\"}",
			pA->X, pA->pB->T);

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST_FLAGS("SIMPLE", kflat_simple_test, kflat_simple_validate, KFLAT_TEST_ATOMIC);

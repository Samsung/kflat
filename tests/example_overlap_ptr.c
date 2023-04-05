/**
 * @file example_overlap_ptr.c
 * @author Samsung R&D Poland - Mobile Security Group
 */

#include "common.h"

typedef struct struct_B {
	int i;
} my_B;

typedef struct struct_A {
	unsigned long ul;
	my_B *pB0;
	my_B *pB1;
	my_B *pB2;
	my_B *pB3;
	char *p;
} my_A;

#ifdef __KERNEL__

/* RECURSIVE version */
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(my_B);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(my_A,
	STRUCT_ALIGN(64);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B, pB0);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B, pB1);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B, pB2);
	AGGREGATE_FLATTEN_STRUCT_TYPE(my_B, pB3);
	AGGREGATE_FLATTEN_STRING(p);
);

static int kflat_overlapptr_test(struct kflat *kflat) {
	int err = 0;
	my_B arrB[4] = { { 1 }, { 2 }, { 3 }, { 4 } };
	my_A T[3] = { {}, { 0, &arrB[0], &arrB[1], &arrB[2], &arrB[3], "p in struct A" }, {} };
	unsigned char *p;

	p = (unsigned char *)&T[1] - 8;
	FOR_ROOT_POINTER(p,
		FLATTEN_TYPE_ARRAY(unsigned char, p, sizeof(my_A) + 16);
	);

	FOR_ROOT_POINTER(&T[1],
		FLATTEN_STRUCT_TYPE(my_A, &T[1]);
	);

	return err;
}

#else

static int kflat_overlapptr_test_validate(void *memory, size_t size, CFlatten flatten) {
	my_A *pA = (my_A *)flatten_root_pointer_seq(flatten, 1);
	ASSERT(pA->pB0->i == 1);
	ASSERT(pA->pB1->i == 2);
	ASSERT(pA->pB2->i == 3);
	ASSERT(pA->pB3->i == 4);
	ASSERT(pA->p && !strcmp(pA->p, "p in struct A"));

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST_FLAGS("OVERLAP_PTR", kflat_overlapptr_test, kflat_overlapptr_test_validate, KFLAT_TEST_ATOMIC);

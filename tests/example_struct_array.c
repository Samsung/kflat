/**
 * @file example_struct_array.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

// Common structures
struct CC {
	int i;
};

struct BB {
	long s;
	long n;
	int *pi;
	struct CC *pC;
};

struct MM {
	const char *s;
	struct BB arrB[4];
	long *Lx;
};

/********************************/
#ifdef __KERNEL__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(CC);

FUNCTION_DEFINE_FLATTEN_STRUCT(BB,
	AGGREGATE_FLATTEN_TYPE_ARRAY(int, pi, ATTR(n));
	AGGREGATE_FLATTEN_STRUCT(CC, pC);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(MM,
	AGGREGATE_FLATTEN_STRING(s);
	for (int __i = 0; __i < 4; ++__i) {
		const struct BB *p = ATTR(arrB) + __i;
		AGGREGATE_FLATTEN_STRUCT_STORAGE(BB, p);
	} 
	AGGREGATE_FLATTEN_TYPE_ARRAY(long, Lx, 0);
);

static int kflat_structarray_example(struct kflat *kflat) {
	struct CC c0 = { 0 }, c1 = { 1000 }, c2 = { 1000000 };
	int T[60] = {};
	struct MM obM = {
		"This is a M object here",
		{
			{ 0, 3, &T[3], &c0 },
			{ 10, 20, &T[10], &c1 },
			{ 15, 40, &T[15], &c2 },
			{ 15, 66, NULL, NULL },
		},
	};
	unsigned char *p = (unsigned char *)&obM;
	unsigned char *q = (unsigned char *)&obM.arrB[3].n;
	size_t q_offset = q - p;

	for (int i = 0; i < 60; ++i)
		T[i] = i;

	FOR_ROOT_POINTER(p,
		FLATTEN_TYPE_ARRAY(unsigned char, p, q_offset);
	);
	FOR_ROOT_POINTER(q,
		FLATTEN_TYPE_ARRAY(unsigned char, p, sizeof(struct MM) - q_offset);
	);
	FOR_ROOT_POINTER(&obM,
		FLATTEN_STRUCT(MM, &obM);
	);

	return 0;
}

#else

static int kflat_structarray_validate(void *memory, size_t size, CFlatten flatten) {
	struct MM *obM = (struct MM *)flatten_root_pointer_seq(flatten, 0);
	long *n = (long *)flatten_root_pointer_seq(flatten, 1);
	struct MM *m2 = (struct MM *)flatten_root_pointer_seq(flatten, 2);

	ASSERT(obM == m2);
	ASSERT(*n == 66);
	ASSERT(!strcmp(obM->s, "This is a M object here"));

	ASSERT(obM->arrB[0].s == 0);
	ASSERT(obM->arrB[1].s == 10);
	ASSERT(obM->arrB[2].s == 15);
	ASSERT(obM->arrB[3].s == 15);

	ASSERT(obM->arrB[0].n == 3);
	ASSERT(obM->arrB[1].n == 20);
	ASSERT(obM->arrB[2].n == 40);
	ASSERT(obM->arrB[3].n == 66);

	ASSERT(obM->arrB[3].pi == NULL);
	ASSERT(obM->arrB[0].pi[0] == 3);
	ASSERT(obM->arrB[1].pi[0] == 10);
	ASSERT(obM->arrB[2].pi[0] == 15);

	ASSERT(obM->arrB[3].pC == NULL);
	ASSERT(obM->arrB[0].pC->i == 0);
	ASSERT(obM->arrB[1].pC->i == 1000);
	ASSERT(obM->arrB[2].pC->i == 1000000);
	return 0;
}

#endif

KFLAT_REGISTER_TEST("STRUCTARRAY", kflat_structarray_example, kflat_structarray_validate);

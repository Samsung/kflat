/**
 * @file example_struct_array.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
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

union K {
	const char* s;
	unsigned long v;
};

struct MM {
	const char *s;
	struct BB arrB[4];
	union K arrK0[2];
	long *Lx;
	int has_s[2];
	union K arrK[2];
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(CC);

FUNCTION_DEFINE_FLATTEN_STRUCT(BB,
	AGGREGATE_FLATTEN_TYPE_ARRAY(int, pi, ATTR(n));
	AGGREGATE_FLATTEN_STRUCT(CC, pC);
);

FUNCTION_DECLARE_FLATTEN_UNION(K);

FUNCTION_DEFINE_FLATTEN_UNION(K,
	if (__cval && ((int*)__cval)[__index]) {
		AGGREGATE_FLATTEN_STRING(s);
	}
);

FUNCTION_DEFINE_FLATTEN_STRUCT(MM,
	AGGREGATE_FLATTEN_STRING(s);
	AGGREGATE_FLATTEN_STRUCT_ARRAY_STORAGE(BB, arrB, 4);
	AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE(K, arrK0, 2);
	AGGREGATE_FLATTEN_TYPE_ARRAY(long, Lx, 0);
	AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_CUSTOM_INFO(K, arrK, 2, ATTR(has_s));
);

static int kflat_structarray_example(struct flat *flat) {
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
		{
			{.v=333333},{.v=444444}
		},
		0,
		{0,1},
		{
			{.v = 999},
			{"999"},
		}
	};
	unsigned char *p = (unsigned char *)&obM;
	unsigned char *q = (unsigned char *)&obM.arrB[3].n;
	size_t q_offset = q - p;

	FLATTEN_SETUP_TEST(flat);

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

	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_structarray_validate(void *memory, size_t size, CUnflatten flatten) {
	struct MM *obM = (struct MM *)unflatten_root_pointer_seq(flatten, 0);
	long *n = (long *)unflatten_root_pointer_seq(flatten, 1);
	struct MM *m2 = (struct MM *)unflatten_root_pointer_seq(flatten, 2);

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

	ASSERT(obM->arrK0[0].v == 333333);
	ASSERT(obM->arrK0[1].v == 444444);

	ASSERT(obM->Lx == 0);

	ASSERT(obM->has_s[0]==0);
	ASSERT(obM->has_s[1]==1);

	ASSERT(obM->arrK[0].v==999);
	ASSERT(!strcmp(obM->arrK[1].s,"999"));

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("STRUCTARRAY", kflat_structarray_example, kflat_structarray_validate, KFLAT_TEST_ATOMIC);

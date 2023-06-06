/**
 * @file example_record_pointer.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct iptr {
	long l;
	int *p;
	struct iptr **pp;
};

static int iarr[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_SELF_CONTAINED(iptr, sizeof(struct iptr));
FUNCTION_DEFINE_FLATTEN_STRUCT_SELF_CONTAINED(iptr, sizeof(struct iptr),
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(int, p, offsetof(struct iptr,p), OFFATTR(long, offsetof(struct iptr,l)));
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct iptr *, pp, offsetof(struct iptr,pp), 1);
	FOR_POINTER(struct iptr *, __iptr_1, /*ATTR(pp)*/ OFFATTR(void **, offsetof(struct iptr,pp)),
		FLATTEN_STRUCT_ARRAY(iptr, __iptr_1, 1); /* not SAFE */
	);
);

int kflat_record_pointer_test(struct flat *flat) {
	struct iptr pv = { 0, 0, 0 };
	struct iptr *ppv = &pv;
	struct iptr pv2 = { 10, iarr, &ppv };

	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(&pv2,
		FLATTEN_STRUCT_ARRAY(iptr, &pv2, 1);
	);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_record_pointer_validate(void *memory, size_t size, CUnflatten flatten) {
	struct iptr *pv2 = (struct iptr *)memory;
	ASSERT(pv2->l == 10);
	ASSERT(!memcmp(pv2->p, iarr, sizeof(iarr)));

	struct iptr *pv = *pv2->pp;
	ASSERT(pv->l == 0);
	ASSERT(pv->p == 0);
	ASSERT(pv->pp == 0);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("RECORD_POINTER", kflat_record_pointer_test, kflat_record_pointer_validate, KFLAT_TEST_ATOMIC);

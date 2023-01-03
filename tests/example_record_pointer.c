/**
 * @file example_record_pointer.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"


struct iptr {
	long l;
	int* p;
	struct iptr** pp;
};

int iarr[10] = {0,1,2,3,4,5,6,7,8,9};


#ifdef __KERNEL__

FUNCTION_DECLARE_FLATTEN_STRUCT_ARRAY_ITER_SELF_CONTAINED(iptr,24);

FUNCTION_DEFINE_FLATTEN_STRUCT_ITER_SELF_CONTAINED(iptr,24,
    AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(int,p,8,OFFATTR(long,0));
	AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(struct iptr*,pp,16,1);
	FOR_POINTER(struct iptr*,__iptr_1,/*ATTR(pp)*/ OFFATTR(void**,16), /* not SAFE */
	  FLATTEN_STRUCT_ARRAY_ITER(iptr,__iptr_1,1);  /* not SAFE */
	);
);


int kflat_record_pointer_test(struct kflat *kflat) {

	struct iptr pv = {0, 0, 0};
	struct iptr* ppv = &pv;
	struct iptr pv2 = {10, iarr, &ppv};

	UNDER_ITER_HARNESS(
		FOR_ROOT_POINTER(&pv2,
			FLATTEN_STRUCT_ARRAY_ITER(iptr, &pv2, 1);
		);
	);

	return 0;
}

#else

static int kflat_record_pointer_validate(void* memory, size_t size, CFlatten flatten) {
    struct iptr* pv2 = (struct iptr*) memory;
	ASSERT(pv2->l == 10);
    ASSERT(!memcmp(pv2->p, iarr, sizeof(iarr)));

    struct iptr* pv = *pv2->pp;
    ASSERT(pv->l == 0);
    ASSERT(pv->p == 0);
    ASSERT(pv->pp == 0);
	return 0;
}

#endif


KFLAT_REGISTER_TEST("RECORD_POINTER", kflat_record_pointer_test, kflat_record_pointer_validate);

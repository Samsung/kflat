/**
 * @file example_pointer.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"


#ifdef __KERNEL__

static int kflat_pointer_test(struct kflat *kflat) {
	double magic_number = 3.14159265359;
	double* pointer_to_it = &magic_number;
	double** pointer_to_pointer_to_it = &pointer_to_it;
	double*** ehhh = &pointer_to_pointer_to_it;

	FOR_ROOT_POINTER(ehhh,
		FLATTEN_TYPE_ARRAY(double**, &pointer_to_pointer_to_it, 1);
		FOREACH_POINTER(double**,p, &pointer_to_pointer_to_it, 1,
			FLATTEN_TYPE_ARRAY(double*, p, 1);
			FOREACH_POINTER(double*, q, p, 1,
				FLATTEN_TYPE_ARRAY(double, q, 1);
			);
		);
	);

	return 0;
}

#else

static int kflat_pointer_validate(void* memory, size_t size, CFlatten flatten) {
    double*** trio = (double***) memory;
    double magic_number = ***trio;
	ASSERT(3.140 <= magic_number && magic_number <= 3.145);
	return 0;
}

#endif


KFLAT_REGISTER_TEST("POINTER", kflat_pointer_test, kflat_pointer_validate);

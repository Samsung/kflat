/**
 * @file example_pointer.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

/********************************/
#ifdef __TESTER__
/********************************/

static int kflat_pointer_test(struct flat *flat) {
	double magic_number = 3.14159265359;
	double *pointer_to_it = &magic_number;
	double **pointer_to_pointer_to_it = &pointer_to_it;
	double ***ehhh = &pointer_to_pointer_to_it;

	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(ehhh,
		FLATTEN_TYPE_ARRAY(double **, &pointer_to_pointer_to_it, 1);
		FOREACH_POINTER(double **, p, &pointer_to_pointer_to_it, 1,
			FLATTEN_TYPE_ARRAY(double *, p, 1);
			FOREACH_POINTER(double *, q, p, 1,
				FLATTEN_TYPE_ARRAY(double, q, 1);
			);
		);
	);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_pointer_validate(void *memory, size_t size, CUnflatten flatten) {

	double ***trio = (double ***)memory;
	double magic_number = ***trio;
	ASSERT(3.140 <= magic_number && magic_number <= 3.145);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("POINTER", kflat_pointer_test, kflat_pointer_validate, KFLAT_TEST_ATOMIC);

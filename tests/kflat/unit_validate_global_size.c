/**
 * @file unit_validate_global_size.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct validate_global_size_results {
	bool test_global_address;
	bool test_global_address_shifted;
	bool test_module_global_address;
	bool test_module_global_address_shifted;
	bool test_invalid_address;
};

/********************************/
#ifdef __TESTER__
/********************************/

int kflat_test_size_global;

FUNCTION_DEFINE_FLATTEN_STRUCT(validate_global_size_results);

static int kflat_global_size_unit_test(struct flat *flat) {
	struct validate_global_size_results results = { 0 };
	unsigned long kernel_test_global_addr = (unsigned long)flatten_global_address_by_name("modules_disabled");

	FLATTEN_SETUP_TEST(flat);

	// Stop copiler from optimizing this global
	memset((void*) &kflat_test_size_global, 0, sizeof(kflat_test_size_global));
	
	results.test_global_address = (flatten_validate_inmem_size(kernel_test_global_addr, sizeof(int)) == 0);
	results.test_global_address_shifted = (flatten_validate_inmem_size(kernel_test_global_addr - 1, sizeof(int)) == 1);
	
	results.test_module_global_address = (flatten_validate_inmem_size((unsigned long) &kflat_test_size_global, sizeof(kflat_test_size_global)) == 0);
	results.test_module_global_address_shifted = (flatten_validate_inmem_size((unsigned long) &kflat_test_size_global - 2, sizeof(kflat_test_size_global)) == 2);

	results.test_invalid_address = (flatten_validate_inmem_size(0xdeadbeef, sizeof(int)) == -EINVAL);

	// Send results back to user
	FOR_ROOT_POINTER(&results,
		FLATTEN_STRUCT(validate_global_size_results, &results);
	);

	return FLATTEN_FINISH_TEST(flat);
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_global_size_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct validate_global_size_results *pResults = (struct validate_global_size_results *)memory;

	ASSERT(pResults->test_global_address);
	ASSERT(pResults->test_global_address_shifted);
	ASSERT(pResults->test_module_global_address);
	ASSERT(pResults->test_module_global_address_shifted);
	ASSERT(pResults->test_invalid_address);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] global_size", kflat_global_size_unit_test, kflat_global_size_unit_validate);

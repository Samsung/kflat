/**
 * @file unit_get_global_address.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct get_global_result {
	bool test_nonexistent_pass;
	bool test_module_global_pass;
	bool test_kernel_global_pass;
	bool test_module_func_pass;
};

/********************************/
#ifdef __TESTER__
/********************************/

int kflat_test_global;

FUNCTION_DEFINE_FLATTEN_STRUCT(get_global_result);

static int kflat_global_addr_unit_test(struct flat *flat) {
	struct get_global_result results = { 0 };

	FLATTEN_SETUP_TEST(flat);

	results.test_nonexistent_pass = (NULL == flatten_global_address_by_name("not_existing_variable_this_is"));
	results.test_module_global_pass = (&kflat_test_global == flatten_global_address_by_name("kflat_core:kflat_test_global"));
	results.test_kernel_global_pass = (NULL != flatten_global_address_by_name("iomem_resource"));
	results.test_module_func_pass = (NULL != flatten_global_address_by_name("kflat_core:kflat_global_addr_unit_test"));

	// Send results back to user
	FOR_ROOT_POINTER(&results,
		FLATTEN_STRUCT(get_global_result, &results);
	);

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_global_addr_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct get_global_result *pResults = (struct get_global_result *)memory;

	ASSERT(pResults->test_nonexistent_pass);
	ASSERT(pResults->test_module_global_pass);
	ASSERT(pResults->test_kernel_global_pass);
	ASSERT(pResults->test_module_func_pass);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] global_address", kflat_global_addr_unit_test, kflat_global_addr_unit_validate);

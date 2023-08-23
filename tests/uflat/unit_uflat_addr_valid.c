/**
 * @file unit_uflat_addr_valid.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * 
 */

#include "common.h"

struct unit_addr_valid_test {
	bool valid_mem;
	bool wild_pointer;
	bool non_readable_mem;
	bool too_small_mem;

	bool exec_mem_valid;
	bool exec_mem_only_rw;
	bool exec_mem_invalid_ptr;
};


/********************************/
#ifdef __TESTER__
/********************************/
#define _GNU_SOURCE
#include <sys/mman.h>
#include <string.h>

FUNCTION_DEFINE_FLATTEN_STRUCT(unit_addr_valid_test);

static int flatten_unit_addr_valid_test(struct flat *flat) {
	struct unit_addr_valid_test results = {0};

	// Test uflat_test_addr_range functoin
	void* valid = mmap(NULL, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if(valid == MAP_FAILED)
		return 1;
	results.valid_mem = uflat_test_address_range(flat, valid, 4096);
	results.wild_pointer = uflat_test_address_range(flat, (void*) 0xcafe0000, 4096);

	void* non_read_mem = mmap(NULL, 4096, 0, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if(non_read_mem == MAP_FAILED)
		return 1;
	results.non_readable_mem = uflat_test_address_range(flat, non_read_mem, 4096);
	results.too_small_mem = uflat_test_address_range(flat, valid, 4097);

	// Test uflat_test_exec_range function
	void* test = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if(test == MAP_FAILED)
		return 1;
	results.exec_mem_valid = uflat_test_exec_range(flat, test);

	void* test2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if(test2 == MAP_FAILED)
		return 1;
	results.exec_mem_only_rw = uflat_test_exec_range(flat, test2);
	results.exec_mem_invalid_ptr = uflat_test_exec_range(flat, (void*) 0xcafecafe);

	// Save results
	FLATTEN_SETUP_TEST(flat);

	FOR_ROOT_POINTER(&results,
		FLATTEN_STRUCT(unit_addr_valid_test, &results);
	);

	munmap(non_read_mem, 4096);
	munmap(valid, 4096);
	munmap(test2, 4096);
	munmap(test, 4096);
	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int flatten_unit_addr_valid_validate(void *memory, size_t size, CUnflatten flatten) {
	struct unit_addr_valid_test *test = (struct unit_addr_valid_test *)unflatten_root_pointer_seq(flatten, 0);

	ASSERT(test->valid_mem);
	ASSERT(!test->wild_pointer);
	ASSERT(!test->non_readable_mem);
	ASSERT(!test->too_small_mem);

	ASSERT(test->exec_mem_valid);
	ASSERT(!test->exec_mem_only_rw);
	ASSERT(!test->exec_mem_invalid_ptr);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] uflat_test_addr_valid", flatten_unit_addr_valid_test, flatten_unit_addr_valid_validate);

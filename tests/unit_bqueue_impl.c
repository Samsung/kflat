/**
 * @file unit_bqueue_impl.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct bqueue_impl_result {
	bool small_test;
	bool chunks_test;
	bool single_large_test;
	bool bounds;
};

#ifdef __KERNEL__

FUNCTION_DEFINE_FLATTEN_STRUCT(bqueue_impl_result);

static int kflat_bqueue_impl_unit_test(struct kflat *kflat) {
	struct bqueue bq;
	struct bqueue_impl_result results = { 0 };
	size_t size = 6;
	char mem[6] = {'a', 'b', 'c', 'd', 'e', '\0'};
	char test[6];
	char* large_mem, *copy_mem;

	// Basic test
	bqueue_init(&kflat->flat, &bq, 1000);
	results.small_test = true;

	for(int i = 0; i < 100; i++)
		bqueue_push_back(&kflat->flat, &bq, mem, size);
	for(int i = 0; i < 100; i++) {
		bqueue_pop_front(&bq, test, size);
		if(memcmp(test, mem, size)) {
			results.small_test = false;
			break;
		}
	}
	bqueue_destroy(&bq);


	// Check chunks creation
	bqueue_init(&kflat->flat, &bq, 1000);
	results.chunks_test = true;

	for(int i = 0; i < 1000; i++)
		bqueue_push_back(&kflat->flat, &bq, mem, size);
	for(int i = 0; i < 1000; i++) {
		bqueue_pop_front(&bq, test, size);
		if(memcmp(test, mem, size)) {
			results.chunks_test = false;
			break;
		}
	}
	bqueue_destroy(&bq);

	// Check data split
	results.single_large_test = true;
	large_mem = flat_zalloc(&kflat->flat, PAGE_SIZE, 1);
	copy_mem = flat_zalloc(&kflat->flat, PAGE_SIZE, 1);
	for(int i = 0; i < PAGE_SIZE; i++)
		copy_mem[i] = large_mem[i] = i;

	bqueue_init(&kflat->flat, &bq, 100);
	
	bqueue_push_back(&kflat->flat, &bq, large_mem, PAGE_SIZE);
	bqueue_pop_front( &bq, test, size);
	for(int i = 0; i < PAGE_SIZE; i++)
		if(copy_mem[i] != large_mem[i]) {
			results.single_large_test = false;
			break;
		}

	bqueue_destroy(&bq);
	
	// Boundary check
	bqueue_init(&kflat->flat, &bq, 100);
	bqueue_push_back(&kflat->flat, &bq, "abcd\0", 5);
	results.bounds = (bqueue_pop_front(&bq, test, 10) != 0);
	bqueue_destroy(&bq);

	// Send results back to user
	FOR_ROOT_POINTER(&results,
		FLATTEN_STRUCT(bqueue_impl_result, &results);
	);

	return 0;
}

#else

static int kflat_bqueue_impl_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	struct bqueue_impl_result *pResults = (struct bqueue_impl_result *)memory;

	ASSERT(pResults->small_test);
	ASSERT(pResults->chunks_test);
	ASSERT(pResults->bounds);
	ASSERT(pResults->single_large_test);

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST("[UNIT] bqueue test", kflat_bqueue_impl_unit_test, kflat_bqueue_impl_unit_validate);

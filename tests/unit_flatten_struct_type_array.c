/**
 * @file unit_flatten_struct_type_array.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

static const char *test_string = "THIS IS A TEST ";

typedef struct {
	int magic;
	char str[16];
} bucket_t;

typedef struct {
	long k;
	void* q;
	char u[12];
} brick_t;

typedef struct {
	bucket_t *tab;
	long long *integers;
	brick_t* brick_tab;
	void* brick_inside_tab;
} box_t;

#ifdef __KERNEL__

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(bucket_t);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(brick_t);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(box_t,
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY(bucket_t, tab, 3);
	AGGREGATE_FLATTEN_TYPE_ARRAY(long long, integers, 10);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED(brick_t,sizeof(brick_t),brick_tab,offsetof(box_t,brick_tab),10);
	AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_SELF_CONTAINED_SHIFTED(brick_t,sizeof(brick_t),brick_inside_tab,offsetof(box_t,brick_inside_tab),5,-offsetof(brick_t,q));
);

static int kflat_flatten_struct_type_array_unit_test(struct kflat *kflat) {
	long long integers[10];
	bucket_t el[3];
	brick_t bricks[20] = {};
	box_t box[2] = {
		{ el, integers, bricks, &bricks[5].q }, { el + 1, integers + 4, bricks+10, &bricks[15].q }
	};

	for (int i = 0; i < 10; i++)
		integers[i] = i * 2;
	for (int i = 0; i < 3; i++) {
		el[i].magic = 0xCAFECAFE + i;
		strcpy(el[i].str, test_string);
	}
	for (int i = 0; i < 20; i++) {
		bricks[i].k = 0x11223344+i;
		snprintf(bricks[i].u,12,"[[%6d]]",11111*i);
	}

	FOR_ROOT_POINTER(box,
		FLATTEN_STRUCT_TYPE_ARRAY(box_t, box, 2);
	);

	// Test ADDR_RANGE_VALID macro
	FOR_ROOT_POINTER(box,
		FLATTEN_STRUCT_TYPE_ARRAY(box_t, box, 10000);
	);

	return 0;
}

#else

static int kflat_flatten_struct_type_array_unit_validate(void *memory, size_t size, CUnflatten flatten) {
	box_t *box = (box_t *)memory;

	ASSERT(box[0].integers + 4 == box[1].integers);
	ASSERT(box[0].tab + 1 == box[1].tab);
	ASSERT(box[0].brick_tab + 10 == box[1].brick_tab);
	ASSERT(box[0].brick_inside_tab-offsetof(brick_t,q) + 10*sizeof(brick_t) == box[1].brick_inside_tab-offsetof(brick_t,q));

	for (int i = 0; i < 10; i++)
		ASSERT(box[0].integers[i] == i * 2);
	for (int i = 0; i < 3; i++) {
		ASSERT(box[0].tab[i].magic == 0xCAFECAFE + i);
		ASSERT(!strcmp(box[0].tab[i].str, test_string));
	}
	for (int i = 0; i < 20; i++) {
		brick_t* brick = box[0].brick_tab+i;
		ASSERT_EQ(brick->k,0x11223344+i);
		ASSERT_EQ(brick->q,0);
		char n[12];
		memset(n,0,12);
		snprintf(n,12,"[[%6d]]",11111*i);
		ASSERT(!strcmp(brick->u,n));
	}

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST_FLAGS("[UNIT] flatten_struct_type_array", kflat_flatten_struct_type_array_unit_test, kflat_flatten_struct_type_array_unit_validate, KFLAT_TEST_ATOMIC);

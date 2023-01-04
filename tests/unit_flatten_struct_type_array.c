/**
 * @file unit_flatten_struct_type_array.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"


static const char* test_string = "THIS IS A TEST ";

typedef struct {
    int magic;
    char str[16];
} bucket_t;

typedef struct {
    bucket_t* tab;
    long long* integers;
} box_t;


#ifdef __KERNEL__

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(bucket_t);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(box_t,
    AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY(bucket_t, tab, 3);
    AGGREGATE_FLATTEN_TYPE_ARRAY(long long, integers, 10);
);

static int kflat_flatten_struct_type_array_unit_test(struct kflat *kflat) {
	long long integers[10];
    bucket_t el[3];
    box_t box[2] = {
        {el, integers}, {el + 1, integers + 4}
    };

    for(int i = 0; i < 10; i++)
        integers[i] = i * 2;
    for(int i = 0; i < 3; i++) {
        el[i].magic = 0xCAFECAFE + i;
        strcpy(el[i].str, test_string);
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

static int kflat_flatten_struct_type_array_unit_validate(void* memory, size_t size, CFlatten flatten) {
    box_t* box = (box_t*) memory;

    ASSERT(box[0].integers + 4 == box[1].integers);
    ASSERT(box[0].tab + 1 == box[1].tab);

    for(int i = 0; i < 10; i++)
        ASSERT(box[0].integers[i] == i * 2);
    for(int i = 0; i < 3; i++) {
        ASSERT(box[0].tab[i].magic == 0xCAFECAFE + i);
        ASSERT(!strcmp(box[0].tab[i].str, test_string));
    }
	return 0;
}

#endif


KFLAT_REGISTER_TEST("[UNIT] flatten_struct_type_array", kflat_flatten_struct_type_array_unit_test, kflat_flatten_struct_type_array_unit_validate);

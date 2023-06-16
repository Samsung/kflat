/**
 * @file unit_aggregate_flatten_struct_shifted.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

struct shifted {
    int     a;
    char    b[4];
    size_t  c;
};
typedef struct shifted shifted_t;

struct storage_for_shifted {
    void* ptr_to_c;
};
typedef struct storage_for_shifted storage_for_shifted_t;


/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(shifted);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(shifted_t);

FUNCTION_DEFINE_FLATTEN_STRUCT(storage_for_shifted,
    AGGREGATE_FLATTEN_STRUCT_SHIFTED(shifted, ptr_to_c , -offsetof(struct shifted, c));
);
FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(storage_for_shifted_t,
    AGGREGATE_FLATTEN_STRUCT_TYPE_SHIFTED(shifted_t, ptr_to_c , -offsetof(shifted_t, c));
);

static int kflat_aggregate_struct_shifted_unit_test(struct flat *flat) {
    struct shifted shifted = {
        .a = 1,
        .b = {'a', 'b', 'c', 'd'},
        .c = 0x55522
    };
    struct storage_for_shifted storage_for_shifted = {
        .ptr_to_c = (void*) &shifted.c
    };

    FLATTEN_SETUP_TEST(flat);

    shifted_t tshifted;
    storage_for_shifted_t tstorage_for_shifted;
    memcpy(&tshifted, &shifted, sizeof(shifted));
    tstorage_for_shifted.ptr_to_c = &tshifted.c;

    FOR_EXTENDED_ROOT_POINTER(&storage_for_shifted, "storage_for_shifted", sizeof(storage_for_shifted),
        FLATTEN_STRUCT(storage_for_shifted, &storage_for_shifted);
    );

    FOR_EXTENDED_ROOT_POINTER(&tstorage_for_shifted, "tstorage_for_shifted", sizeof(tstorage_for_shifted),
        FLATTEN_STRUCT_TYPE(storage_for_shifted_t, &tstorage_for_shifted);
    );

    return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_aggregate_struct_shifted_unit_validate(void *memory, size_t size, CUnflatten flatten) {
    struct storage_for_shifted *storage_for_shifted = (struct storage_for_shifted *)unflatten_root_pointer_seq(flatten, 0);
	storage_for_shifted_t *tstorage_for_shifted = (storage_for_shifted_t*)unflatten_root_pointer_seq(flatten, 1);

    struct shifted* shifted = (struct shifted*) ((char*) storage_for_shifted->ptr_to_c - offsetof(struct shifted, c));
    shifted_t* tshifted = (shifted_t*) ((char*) tstorage_for_shifted->ptr_to_c - offsetof(shifted_t, c));

    ASSERT_EQ(shifted->a, 1);
    for(int i = 0; i < 4; i++)
        ASSERT_EQ(shifted->b[i], 'a' + i);
    ASSERT_EQ(shifted->c, 0x55522);

    ASSERT_EQ(tshifted->a, 1);
    for(int i = 0; i < 4; i++)
        ASSERT_EQ(tshifted->b[i], 'a' + i);
    ASSERT_EQ(tshifted->c, 0x55522);

    return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST("[UNIT] aggregate_flatten_shifted", kflat_aggregate_struct_shifted_unit_test, kflat_aggregate_struct_shifted_unit_validate);

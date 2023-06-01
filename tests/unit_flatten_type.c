/**
 * @file unit_flatten_type.c
 * @author Samsung R&D Poland - Mobile Security Group
 *
 */

#include "common.h"

unsigned long magic = 0xCAFEBEEF;
char garr[20];

struct tpX {
    long* larr;
    short* sarr;
    float* f1;
    float* f2;
};

#ifdef __KERNEL__

FUNCTION_DEFINE_FLATTEN_STRUCT(tpX,
    AGGREGATE_FLATTEN_TYPE_ARRAY(long,larr,4);
    AGGREGATE_FLATTEN_TYPE_ARRAY_SELF_CONTAINED(short,sarr,offsetof(struct tpX,sarr),8);
    AGGREGATE_FLATTEN_TYPE(float,f1);
    AGGREGATE_FLATTEN_TYPE_SELF_CONTAINED(float,f2,offsetof(struct tpX,f2));
);

static int kflat_flatten_type_unit_test(struct kflat *kflat) {

    long larr[4] = {-1000,-500,500,1000};
    short sarr[8] = {2,4,6,8,-900,-920,-940,-960};
    float farr[4] = {1.0,2.0,3.0,4.0};
    struct tpX x = { larr, sarr, &farr[1], &farr[3] };

    memcpy(garr,"ABCDEFGHIJKLMNOPQRS",20);

    FOR_ROOT_POINTER(&garr,
        FLATTEN_TYPE_ARRAY(char,&garr,20);
    );

    FOR_ROOT_POINTER(&magic,
        FLATTEN_TYPE(unsigned long,&magic);
    );

    FOR_ROOT_POINTER(&x,
        FLATTEN_STRUCT(tpX,&x);
    );

	return 0;
}

#else

static int kflat_flatten_struct_type_validate(void *memory, size_t size, CUnflatten flatten) {

    const char* gs = (const char*)unflatten_root_pointer_seq(flatten, 0);
    unsigned long* gm = (unsigned long*)unflatten_root_pointer_seq(flatten, 1);
    struct tpX* gx = (struct tpX*)unflatten_root_pointer_seq(flatten, 2);

    ASSERT(!memcmp(gs,"ABCDEFGHIJKLMNOPQRS",20));
    ASSERT_EQ(*gm,0xCAFEBEEF);

    ASSERT_EQ(gx->larr[0],-1000);
    ASSERT_EQ(gx->larr[1],-500);
    ASSERT_EQ(gx->larr[2],500);
    ASSERT_EQ(gx->larr[3],1000);

    ASSERT_EQ(gx->sarr[0],2);
    ASSERT_EQ(gx->sarr[1],4);
    ASSERT_EQ(gx->sarr[2],6);
    ASSERT_EQ(gx->sarr[3],8);
    ASSERT_EQ(gx->sarr[4],-900);
    ASSERT_EQ(gx->sarr[5],-920);
    ASSERT_EQ(gx->sarr[6],-940);
    ASSERT_EQ(gx->sarr[7],-960);

    ASSERT_EQ(*gx->f1,2.0);
    ASSERT_EQ(*gx->f2,4.0);

	return KFLAT_TEST_SUCCESS;
}

#endif

KFLAT_REGISTER_TEST_FLAGS("[UNIT] flatten_type", kflat_flatten_type_unit_test, kflat_flatten_struct_type_validate, KFLAT_TEST_ATOMIC);

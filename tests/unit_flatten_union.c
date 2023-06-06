/**
 * @file unit_flatten_union.c
 * @author Samsung R&D Poland - Mobile Security Group
 *
 */

#include "common.h"

union uA {
    long c;
    int k;
};

struct my_unions {
    union uA* uAtab;
    void* othertab;
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_UNION_SELF_CONTAINED(uA,sizeof(union uA));

FUNCTION_DEFINE_FLATTEN_STRUCT(my_unions,
    AGGREGATE_FLATTEN_UNION_ARRAY_SELF_CONTAINED(uA,sizeof(union uA),uAtab,offsetof(struct my_unions,uAtab),3);
);

static int kflat_flatten_union_unit_test(struct flat *flat) {

    union uA utab[3] = {{7},{8},{9}};
    union uA utab2[3] = {{-1},{0},{1}};
    struct my_unions mu = {utab2};

    FLATTEN_SETUP_TEST(flat);

    FOR_ROOT_POINTER(utab,
        FLATTEN_UNION_ARRAY_SELF_CONTAINED(uA,sizeof(union uA),utab,3);
    );

    FOR_ROOT_POINTER(&mu,
        FLATTEN_STRUCT(my_unions,&mu);
    );

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_union_unit_validate(void *memory, size_t size, CUnflatten flatten) {

    union uA* puA = (union uA*)unflatten_root_pointer_seq(flatten, 0);
    struct my_unions* pmu = (struct my_unions*)unflatten_root_pointer_seq(flatten, 1);

    ASSERT_EQ(puA[0].c,7);
    ASSERT_EQ(puA[1].c,8);
    ASSERT_EQ(puA[2].c,9);

    ASSERT_EQ(pmu->uAtab[0].c,-1);
    ASSERT_EQ(pmu->uAtab[1].c,0);
    ASSERT_EQ(pmu->uAtab[2].c,1);

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("[UNIT] flatten_union", kflat_flatten_union_unit_test, kflat_flatten_union_unit_validate, KFLAT_TEST_ATOMIC);

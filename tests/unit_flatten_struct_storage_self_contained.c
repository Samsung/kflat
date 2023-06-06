/**
 * @file unit_flatten_struct_storage_self_contained.c
 * @author Samsung R&D Poland - Mobile Security Group
 *
 */

#include "common.h"

struct CCS {
    int i;
};

struct BBS {
    long s;
    long n;
    int *pi;
    struct CCS *pC;
};

union KS {
    const char* s;
    unsigned long v;
};

struct MMS {
    const char *s;
    struct BBS arrB[4];
    union KS arrK0[2];
    long *Lx;
    int has_s[2];
    union KS arrK[2];
};

typedef struct {
    const char* s;
} string_s_t;

union SKS {
    string_s_t us;
};

struct str_s {
    const char* s;
};

struct SAS {
    long l;
    union SKS u;
    union SKS w;
    struct str_s ss;
    string_s_t sarr[4];
    char c[10];
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT(CCS);

FUNCTION_DEFINE_FLATTEN_STRUCT(BBS,
    AGGREGATE_FLATTEN_TYPE_ARRAY(int, pi, ATTR(n));
    AGGREGATE_FLATTEN_STRUCT(CCS, pC);
);

FUNCTION_DECLARE_FLATTEN_UNION(KS);

FUNCTION_DEFINE_FLATTEN_UNION(KS,
    if (__cval && ((int*)__cval)[__index]) {
        AGGREGATE_FLATTEN_STRING(s);
    }
);

FUNCTION_DEFINE_FLATTEN_STRUCT(MMS,
    AGGREGATE_FLATTEN_STRING(s);
    AGGREGATE_FLATTEN_STRUCT_ARRAY_STORAGE_SELF_CONTAINED(BBS, sizeof(struct BBS), arrB, offsetof(struct MMS,arrB), 4);
    AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_SELF_CONTAINED(KS, sizeof(union KS), arrK0, offsetof(struct MMS,arrK0), 2);
    AGGREGATE_FLATTEN_TYPE_ARRAY(long, Lx, 0);
    AGGREGATE_FLATTEN_UNION_ARRAY_STORAGE_CUSTOM_INFO_SELF_CONTAINED(KS, sizeof(union KS), arrK, offsetof(struct MMS,arrK), 2, ATTR(has_s));
);

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(string_s_t,
    AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(str_s,
    AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_UNION(SKS,
    AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE_SELF_CONTAINED(string_s_t,sizeof(string_s_t),us,offsetof(union SKS,us));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(SAS,
    AGGREGATE_FLATTEN_UNION_STORAGE_SELF_CONTAINED(SKS,sizeof(union SKS),u,offsetof(struct SAS,u));
    AGGREGATE_FLATTEN_UNION_STORAGE_CUSTOM_INFO_SELF_CONTAINED(SKS,sizeof(union SKS),w,offsetof(struct SAS,w),&ATTR(l));
    AGGREGATE_FLATTEN_STRUCT_STORAGE_SELF_CONTAINED(str_s,sizeof(struct str_s),ss,offsetof(struct SAS,ss));
    AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_STORAGE_SELF_CONTAINED(string_s_t,sizeof(string_s_t),sarr,offsetof(struct SAS,sarr),4);
);

static int kflat_flatten_struct_storage_self_contained_unit_test(struct flat *flat) {

    struct CCS c0 = { 0 }, c1 = { 1000 }, c2 = { 1000000 };
    int T[60] = {};
    struct MMS obM = {
        "This is a M object here",
        {
            { 0, 3, &T[3], &c0 },
            { 10, 20, &T[10], &c1 },
            { 15, 40, &T[15], &c2 },
            { 15, 66, NULL, NULL },
        },
        {
            {.v=333333},{.v=444444}
        },
        0,
        {0,1},
        {
            {.v = 999},
            {"999"},
        }
    };
    struct SAS sa = { 0x34569872, {{"in_union"}}, {{"in_union2"}}, {"BADDCAFE"}, {{"0"},{"1"},{"2"},{"3"}}, "DEADBEEF" };

    FLATTEN_SETUP_TEST(flat);

    for (int i = 0; i < 60; ++i)
        T[i] = i;

    FOR_ROOT_POINTER(&obM,
        FLATTEN_STRUCT(MMS, &obM);
    );

    FOR_ROOT_POINTER(&sa,
        FLATTEN_STRUCT(SAS, &sa);
    );

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_struct_storage_self_contained_unit_validate(void *memory, size_t size, CUnflatten flatten) {

    struct MMS *obM = (struct MMS *)unflatten_root_pointer_seq(flatten, 0);
    struct SAS *sa = (struct SAS *)unflatten_root_pointer_seq(flatten, 1);

    ASSERT(!strcmp(obM->s, "This is a M object here"));

    ASSERT(obM->arrB[0].s == 0);
    ASSERT(obM->arrB[1].s == 10);
    ASSERT(obM->arrB[2].s == 15);
    ASSERT(obM->arrB[3].s == 15);

    ASSERT(obM->arrB[0].n == 3);
    ASSERT(obM->arrB[1].n == 20);
    ASSERT(obM->arrB[2].n == 40);
    ASSERT(obM->arrB[3].n == 66);

    ASSERT(obM->arrB[3].pi == NULL);
    ASSERT(obM->arrB[0].pi[0] == 3);
    ASSERT(obM->arrB[1].pi[0] == 10);
    ASSERT(obM->arrB[2].pi[0] == 15);

    ASSERT(obM->arrB[3].pC == NULL);
    ASSERT(obM->arrB[0].pC->i == 0);
    ASSERT(obM->arrB[1].pC->i == 1000);
    ASSERT(obM->arrB[2].pC->i == 1000000);

    ASSERT(obM->arrK0[0].v == 333333);
    ASSERT(obM->arrK0[1].v == 444444);

    ASSERT(obM->Lx == 0);

    ASSERT(obM->has_s[0]==0);
    ASSERT(obM->has_s[1]==1);

    ASSERT(obM->arrK[0].v==999);
    ASSERT(!strcmp(obM->arrK[1].s,"999"));

    ASSERT_EQ(sa->l,0x34569872);
    ASSERT(!strcmp(sa->u.us.s,"in_union"));
    ASSERT(!strcmp(sa->w.us.s,"in_union2"));
    ASSERT(!strcmp(sa->ss.s,"BADDCAFE"));
    ASSERT(!strcmp(sa->sarr[0].s,"0"));
    ASSERT(!strcmp(sa->sarr[1].s,"1"));
    ASSERT(!strcmp(sa->sarr[2].s,"2"));
    ASSERT(!strcmp(sa->sarr[3].s,"3"));
    ASSERT(!strcmp(sa->c,"DEADBEEF"));

	return KFLAT_TEST_SUCCESS;
}

/********************************/
#endif /* __VALIDATOR__ */
/********************************/

KFLAT_REGISTER_TEST_FLAGS("[UNIT] flatten_struct_storage_self_contained", kflat_flatten_struct_storage_self_contained_unit_test, kflat_flatten_struct_storage_self_contained_unit_validate, KFLAT_TEST_ATOMIC);

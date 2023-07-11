/**
 * @file unit_flatten_struct_storage.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 *
 */

#include "common.h"

typedef struct {
    const char* s;
} string_t;

union SK {
    string_t us;
};

struct str {
    const char* s;
};

struct SA {
    long l;
    union SK u;
    union SK w;
    struct str ss;
    string_t sarr[4];
    char c[10];
};

/********************************/
#ifdef __TESTER__
/********************************/

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(string_t,
    AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(str,
    AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_UNION(SK,
    AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE(string_t,us);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(SA,
    AGGREGATE_FLATTEN_UNION_STORAGE(SK,u);
    AGGREGATE_FLATTEN_UNION_STORAGE_CUSTOM_INFO(SK,w,&ATTR(l));
    AGGREGATE_FLATTEN_STRUCT_STORAGE(str,ss);
    AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_STORAGE(string_t,sarr,4);
);

static int kflat_flatten_struct_storage_unit_test(struct flat *flat) {

    struct SA sa = { 0x34569872, {{"in_union"}}, {{"in_union2"}}, {"BADDCAFE"}, {{"0"},{"1"},{"2"},{"3"}}, "DEADBEEF" };

    FLATTEN_SETUP_TEST(flat);

    FOR_ROOT_POINTER(&sa,
        FLATTEN_STRUCT(SA, &sa);
    );

	return 0;
}

/********************************/
#endif /* __TESTER__ */
#ifdef __VALIDATOR__
/********************************/

static int kflat_flatten_struct_storage_unit_validate(void *memory, size_t size, CUnflatten flatten) {

    struct SA* sa = (struct SA*)memory;

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

KFLAT_REGISTER_TEST_FLAGS("[UNIT] flatten_struct_storage", kflat_flatten_struct_storage_unit_test, kflat_flatten_struct_storage_unit_validate, KFLAT_TEST_ATOMIC);

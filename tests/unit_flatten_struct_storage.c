/**
 * @file unit_flatten_struct_storage.c
 * @author Samsung R&D Poland - Mobile Security Group
 * 
 */

#include "common.h"

typedef struct {
    const char* s;
} string_t;

union SK {
    string_t us;
};

struct SA {
    long l;
    union SK u;
    string_t sarr[4];
    char c[10];
};

#ifdef __KERNEL__

FUNCTION_DEFINE_FLATTEN_STRUCT_TYPE(string_t,
    AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_UNION(SK,
    AGGREGATE_FLATTEN_STRUCT_TYPE_STORAGE(string_t,us);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(SA,
    AGGREGATE_FLATTEN_UNION_STORAGE(SK,u);
    AGGREGATE_FLATTEN_STRUCT_TYPE_ARRAY_STORAGE(string_t,sarr,4);
);

static int kflat_flatten_struct_storage_unit_test(struct kflat *kflat) {
	
    struct SA sa = { 0x34569872, {{"in_union"}}, {{"0"},{"1"},{"2"},{"3"}}, "DEADBEEF" };

    FOR_ROOT_POINTER(&sa,
        FLATTEN_STRUCT(SA, &sa);
    );

	return 0;
}

#else

static int kflat_flatten_struct_storage_unit_validate(void *memory, size_t size, CFlatten flatten) {

    struct SA* sa = (struct SA*)memory;

    ASSERT_EQ(sa->l,0x34569872);
    ASSERT(!strcmp(sa->u.us.s,"in_union"));
    ASSERT(!strcmp(sa->sarr[0].s,"0"));
    ASSERT(!strcmp(sa->sarr[1].s,"1"));
    ASSERT(!strcmp(sa->sarr[2].s,"2"));
    ASSERT(!strcmp(sa->sarr[3].s,"3"));
    ASSERT(!strcmp(sa->c,"DEADBEEF"));

	return 0;
}

#endif

KFLAT_REGISTER_TEST("[UNIT] flatten_struct_storage", kflat_flatten_struct_storage_unit_test, kflat_flatten_struct_storage_unit_validate);

#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"

struct fptr_test_struct {
	int i;
	long l;
	char* s;
};
FUNCTION_DEFINE_FLATTEN_STRUCT(fptr_test_struct,
	AGGREGATE_FLATTEN_STRING(s);
);

static void handler(struct kflat* kflat, struct probe_regs* regs) {
    struct fptr_test_struct test_ptr = {
        .i = 1,
        .l = 0x324,
        .s = "test string"
    };

    FOR_ROOT_POINTER(&test_ptr,
        FLATTEN_STRUCT(fptr_test_struct, &test_ptr);
    );    
}

KFLAT_RECIPE_LIST(
    KFLAT_RECIPE("random_read", handler)
);

KFLAT_RECIPE_MODULE("test module for random_read");


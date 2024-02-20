#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"
#include "kflat_uapi.h"

struct array_element {
    int l;
};

struct inner_struct {
    int k;
    char str[256];
    struct array_element *tab;
    int array_size;
};

struct outer_struct {
    int a;
    int b;
    struct inner_struct *inner;
};

FUNCTION_DECLARE_FLATTEN_STRUCT(array_element);

FUNCTION_DEFINE_FLATTEN_STRUCT(inner_struct, 
    AGGREGATE_FLATTEN_TYPE_ARRAY(struct array_element, tab, ATTR(array_size));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(outer_struct,
	AGGREGATE_FLATTEN_STRUCT(inner_struct, inner);
);

static void handler(struct kflat* kflat, struct probe_regs* regs) {
    struct outer_struct *ptr = (struct outer_struct*) regs->arg3;
    FOR_USER_ROOT_POINTER(ptr,
        FLATTEN_STRUCT(outer_struct, ptr);
    );    
}

KFLAT_RECIPE_LIST(
    KFLAT_RECIPE("test_ioctl", handler)
);

KFLAT_RECIPE_MODULE("An example module to test userspace memory flattening from kernel.");


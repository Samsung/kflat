#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"


FUNCTION_DEFINE_FLATTEN_STRUCT(kernfs_node,
    AGGREGATE_FLATTEN_STRING(name);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(kobject,
    AGGREGATE_FLATTEN_STRING(name);
    AGGREGATE_FLATTEN_STRUCT(kernfs_node, sd);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(module,
	AGGREGATE_FLATTEN_STRING(name);
	AGGREGATE_FLATTEN_STRING(version);
	AGGREGATE_FLATTEN_STRUCT(kobject, holders_dir);
);

// Create base handler that will be invoked in instrumented function
//  flatten_init, flatten_write and flatten_fini were/will be invoked by
//  kflat core module, so they shouldn't be added here.
// Access instrumented func args by using fields arg0, arg1, ... in regs
static void handler(struct kflat* kflat, struct probe_regs* regs) {
    struct module* mod = (void*) regs->arg1;

    // // Dump structure
    FOR_EXTENDED_ROOT_POINTER(mod, "do_init_module", sizeof(*mod),
        FLATTEN_STRUCT(module, mod);
    );
}

KFLAT_RECIPE_LIST(
    KFLAT_RECIPE("do_init_module", handler),
);
KFLAT_RECIPE_MODULE("Kflat recipe for dumping struct module info when loading.");
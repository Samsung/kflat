/**
 * @file memory_map_recipe.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Example kflat recipe hooking into kflat itself and dumping
 *  kernel's memory map
 * 
 */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"


// Declare recipes for required data_types
FUNCTION_DECLARE_FLATTEN_STRUCT(kdump_memory_node);
FUNCTION_DEFINE_FLATTEN_STRUCT(kdump_memory_node,
	AGGREGATE_FLATTEN_STRUCT_EMBEDDED_POINTER(kdump_memory_node, rb.__rb_parent_color, ptr_clear_2lsb_bits, flatten_ptr_restore_2lsb_bits);
    AGGREGATE_FLATTEN_STRUCT(kdump_memory_node, rb.rb_right);
    AGGREGATE_FLATTEN_STRUCT(kdump_memory_node, rb.rb_left);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(kdump_memory_map,
    AGGREGATE_FLATTEN_STRUCT(kdump_memory_node, imap_root.rb_root.rb_node);
    AGGREGATE_FLATTEN_STRUCT(kdump_memory_node, imap_root.rb_leftmost);
);


// Create base handler that will be invoked in instrumented function
//  flatten_init, flatten_write and flatten_fini were/will be invoked by
//  kflat core module, so they shouldn't be added here.
// Access instrumented func args by using fields arg0, arg1, ... in regs
static void handler(struct kflat* kflat, struct probe_regs* regs) {
    struct kdump_memory_map* kdump = (void*) regs->arg1;

    // Dump structure
    FOR_EXTENDED_ROOT_POINTER(kdump, "memory_map", sizeof(*kdump),
        FLATTEN_STRUCT(kdump_memory_map, kdump);
    );
}

// Declaration of instrumented functions
KFLAT_RECIPE_LIST(
    KFLAT_RECIPE("kdump_tree_destroy", handler)
);
KFLAT_RECIPE_MODULE("Example module dumping kernel's VA memory map");

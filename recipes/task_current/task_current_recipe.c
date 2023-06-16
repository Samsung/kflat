/**
 * @file task_current_recipe.c
 * @author Pawel Wieczorek (p.wieczorek@samsung.com)
 * @brief Example kflat recipe flattening selected fields from task_struct
 * 
 */
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"

// Declare helper structure storing offsets of task_struct members
#define OFFSET_VAR(X)   off_t off_ ## X
#define OFFSET_INIT(X)  .off_ ## X = offsetof(struct task_struct, X)
struct task_struct_info {
    OFFSET_VAR(pid);
    OFFSET_VAR(tgid);
    OFFSET_VAR(on_cpu);
    OFFSET_VAR(prio);
    OFFSET_VAR(comm);
    OFFSET_VAR(flags);
    OFFSET_VAR(utime);
    OFFSET_VAR(stime);
    OFFSET_VAR(tasks);
};

// Declare recipes for required data types
FUNCTION_DECLARE_FLATTEN_STRUCT(task_struct);

FUNCTION_DEFINE_FLATTEN_STRUCT(task_struct,
    AGGREGATE_FLATTEN_STRUCT_SHIFTED(task_struct,tasks.prev,-offsetof(struct task_struct,tasks));
    AGGREGATE_FLATTEN_STRUCT_SHIFTED(task_struct,tasks.next,-offsetof(struct task_struct,tasks));
);

FUNCTION_DEFINE_FLATTEN_STRUCT(task_struct_info);

// Handler dumping task_struct
static void task_struct_handler(struct kflat* kflat, struct probe_regs* regs) {
    struct task_struct* init = &init_task;
    struct task_struct_info task_offsets = {
        OFFSET_INIT(pid),
        OFFSET_INIT(tgid),
        OFFSET_INIT(on_cpu),
        OFFSET_INIT(prio),
        OFFSET_INIT(comm),
        OFFSET_INIT(flags),
        OFFSET_INIT(utime),
        OFFSET_INIT(stime),
        OFFSET_INIT(tasks),
    };
    
    FOR_EXTENDED_ROOT_POINTER(init, "init_task", sizeof(struct task_struct),
        FLATTEN_STRUCT(task_struct, init);
    );

    FOR_EXTENDED_ROOT_POINTER(&task_offsets, "task_struct_info", sizeof(struct task_struct_info),
        FLATTEN_STRUCT(task_struct_info, &task_offsets);
    );
}

// Declaration of instrumented functions
KFLAT_RECIPE_LIST(
    KFLAT_RECIPE("task_struct_example", task_struct_handler)
);
KFLAT_RECIPE_MODULE("Example module dumping selected set of fields from task_struct");

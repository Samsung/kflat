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
    OFFSET_VAR(last_wakee);
    OFFSET_VAR(real_parent);
    OFFSET_VAR(parent);
    OFFSET_VAR(group_leader);
    OFFSET_VAR(pi_top_task);
    OFFSET_VAR(oom_reaper_list);

    OFFSET_VAR(pid);
    OFFSET_VAR(tgid);
    OFFSET_VAR(cpu);
    OFFSET_VAR(prio);
    OFFSET_VAR(comm);
};

// Declare recipes for required data types
FUNCTION_DECLARE_FLATTEN_STRUCT(task_struct);

FUNCTION_DEFINE_FLATTEN_STRUCT(task_struct,
		AGGREGATE_FLATTEN_STRUCT(task_struct,last_wakee);
		AGGREGATE_FLATTEN_STRUCT(task_struct,real_parent);
		AGGREGATE_FLATTEN_STRUCT(task_struct,parent);
		AGGREGATE_FLATTEN_STRUCT(task_struct,group_leader);
		AGGREGATE_FLATTEN_STRUCT(task_struct,pi_top_task);
		AGGREGATE_FLATTEN_STRUCT(task_struct,oom_reaper_list);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(task_struct_info);

// Handler invoked before random_read
static void random_read_handler(struct kflat* kflat, struct probe_regs* regs) {
    struct task_struct* task = get_current();
    struct task_struct_info task_offsets = {
        OFFSET_INIT(last_wakee),
        OFFSET_INIT(real_parent),
        OFFSET_INIT(parent),
        OFFSET_INIT(group_leader),
        OFFSET_INIT(pi_top_task),
        OFFSET_INIT(oom_reaper_list),

        OFFSET_INIT(pid),
        OFFSET_INIT(tgid),
        OFFSET_INIT(cpu),
        OFFSET_INIT(prio),
        OFFSET_INIT(comm),
    };
    
    FOR_EXTENDED_ROOT_POINTER(task, "task_struct", sizeof(struct task_struct),
        FLATTEN_STRUCT(task_struct, task);
    );

    FOR_EXTENDED_ROOT_POINTER(&task_offsets, "task_struct_info", sizeof(struct task_struct_info),
        FLATTEN_STRUCT(task_struct_info, &task_offsets);
    );
}


// Declaration of instrumented functions
KFLAT_RECIPE_LIST(
    KFLAT_RECIPE("random_read", random_read_handler)
);
KFLAT_RECIPE_MODULE("Example module dumping selected set of fields from task_struct");


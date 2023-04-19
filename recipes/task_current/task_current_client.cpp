/**
 * @brief 
 * 
 */
#include <cstdio>
#include <set>

#include <unflatten.hpp>

#define OFFSET_VAR(X)   off_t off_ ## X
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

struct task_struct;
#define TASK_STRUCT(tsk, info, field, type)   *(type*)((char*)tsk + info->off_ ## field)


void walk_task_struct(struct task_struct* tsk, struct task_struct_info* info, std::set<struct task_struct*> &visited) {
    visited.insert(tsk);
    printf("T[%d:%d], cpu: %u, prio: %d, comm: %s\n", 
        TASK_STRUCT(tsk, info, pid, int),
        TASK_STRUCT(tsk, info, tgid, int),
        TASK_STRUCT(tsk, info, cpu, unsigned int),
        TASK_STRUCT(tsk, info, prio, int),
        &TASK_STRUCT(tsk, info, comm, char)
    );

    if(TASK_STRUCT(tsk, info, last_wakee, struct task_struct*) != NULL 
        && visited.find(TASK_STRUCT(tsk, info, last_wakee, struct task_struct*)) == visited.end()) {
        walk_task_struct(TASK_STRUCT(tsk, info, last_wakee, struct task_struct*), info, visited);
    }

    if(TASK_STRUCT(tsk, info, real_parent, struct task_struct*) != NULL 
        && visited.find(TASK_STRUCT(tsk, info, real_parent, struct task_struct*)) == visited.end()) {
        walk_task_struct(TASK_STRUCT(tsk, info, real_parent, struct task_struct*), info, visited);
    }

    if(TASK_STRUCT(tsk, info, parent, struct task_struct*) != NULL 
        && visited.find(TASK_STRUCT(tsk, info, parent, struct task_struct*)) == visited.end()) {
        walk_task_struct(TASK_STRUCT(tsk, info, parent, struct task_struct*), info, visited);
    }

    if(TASK_STRUCT(tsk, info, group_leader, struct task_struct*) != NULL 
        && visited.find(TASK_STRUCT(tsk, info, group_leader, struct task_struct*)) == visited.end()) {
        walk_task_struct(TASK_STRUCT(tsk, info, group_leader, struct task_struct*), info, visited);
    }

    if(TASK_STRUCT(tsk, info, pi_top_task, struct task_struct*) != NULL 
        && visited.find(TASK_STRUCT(tsk, info, pi_top_task, struct task_struct*)) == visited.end()) {
        walk_task_struct(TASK_STRUCT(tsk, info, pi_top_task, struct task_struct*), info, visited);
    }

    if(TASK_STRUCT(tsk, info, oom_reaper_list, struct task_struct*) != NULL 
        && visited.find(TASK_STRUCT(tsk, info, oom_reaper_list, struct task_struct*)) == visited.end()) {
        walk_task_struct(TASK_STRUCT(tsk, info, oom_reaper_list, struct task_struct*), info, visited);
    }
}

/*
 * App entry point
 */
int main(int argc, char** argv) {

    if(argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    FILE* file = fopen(argv[1], "rb");
    if(file == NULL) {
        perror("Failed to open input file");
        return 1;
    }

    Flatten flatten;
    flatten.load(file);
    printf("Loaded input file %s\n", argv[1]);
    fclose(file);

    struct task_struct* task_struct = (struct task_struct*) flatten.get_named_root("task_struct", NULL);
    if(task_struct == NULL) {
        fprintf(stderr, "Failed to locate task_struct in loaded file\n");
        return 1;
    }

    struct task_struct_info* info = (struct task_struct_info*) flatten.get_named_root("task_struct_info", NULL);
    if(info == NULL) {
        fprintf(stderr, "Failed to locate task_struct_info in loaded file\n");
        return 1;
    }

    std::set<struct task_struct*> visited;
    walk_task_struct(task_struct, info, visited);

    return 0;
}

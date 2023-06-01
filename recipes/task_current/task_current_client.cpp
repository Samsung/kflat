/**
 * @brief 
 * 
 */
#include <cstdio>
#include <cinttypes>
#include <set>

#include <unflatten.hpp>

#define OFFSET_VAR(X)   off_t off_ ## X
struct task_struct_info {
    OFFSET_VAR(pid);
    OFFSET_VAR(tgid);
    OFFSET_VAR(cpu);
    OFFSET_VAR(prio);
    OFFSET_VAR(comm);
    OFFSET_VAR(flags);
    OFFSET_VAR(utime);
    OFFSET_VAR(stime);
    OFFSET_VAR(tasks);
};

struct task_struct;
#define TASK_STRUCT(tsk, info, field, type)   (*(type*)((unsigned char*)tsk + info->off_ ## field))

static void print_task_struct(struct task_struct* tsk, struct task_struct_info* info) {

    printf("T[%d:%d], cpu: %u, prio: %d, comm: %s, flags: %u, utime: %" PRIu64 ", stime: %" PRIu64 "\n",
        TASK_STRUCT(tsk, info, pid, int),
        TASK_STRUCT(tsk, info, tgid, int),
        TASK_STRUCT(tsk, info, cpu, unsigned int),
        TASK_STRUCT(tsk, info, prio, int),
        &TASK_STRUCT(tsk, info, comm, char),
        TASK_STRUCT(tsk, info, flags, unsigned int),
        TASK_STRUCT(tsk, info, utime, uint64_t),
        TASK_STRUCT(tsk, info, stime, uint64_t)
    );
}

#define next_task(__task,__info)   ((struct task_struct*)(TASK_STRUCT(__task, __info, tasks, unsigned char*)-__info->off_tasks))

void list_task_struct(struct task_struct* init_tsk, struct task_struct_info* info) {

    struct task_struct* p;
    unsigned long task_count = 0;
    for (p = init_tsk; (p = next_task(p,info)) != init_tsk ; ) {
        task_count++;
    }

    printf("## Found %lu tasks\n",task_count);
    for (p = init_tsk; (p = next_task(p,info)) != init_tsk ; ) {
        print_task_struct(p,info);
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

    Unflatten flatten;
    flatten.load(file);
    printf("Loaded input file %s\n", argv[1]);
    fclose(file);

    struct task_struct* init_task_struct = (struct task_struct*) flatten.get_named_root("init_task", NULL);
    if(init_task_struct == NULL) {
        fprintf(stderr, "Failed to locate init task_struct in loaded file\n");
        return 1;
    }

    struct task_struct_info* info = (struct task_struct_info*) flatten.get_named_root("task_struct_info", NULL);
    if(info == NULL) {
        fprintf(stderr, "Failed to locate task_struct_info in loaded file\n");
        return 1;
    }

    list_task_struct(init_task_struct, info);

    return 0;
}

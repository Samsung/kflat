/*
 * Samsung R&D Poland - Mobile Security Group
 */

#include "kflat_uapi.h"
#include "common.h"

#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>


#define KFLAT_NODE      "/sys/kernel/debug/kflat"

#define ARRAY_SIZE(X)       (sizeof(X) / sizeof(X[0]))

/*******************************************************
 * INTERFACES
 *******************************************************/
int interface_read(int fd) {
    char buffer[512];
    return read(fd, buffer, sizeof(buffer));
}

int interface_write(int fd) {
    char buffer[512] = {'a', 0};
    return write(fd, buffer, sizeof(buffer));
}

int interface_ioctl(int fd) {
    return ioctl(fd, 0, 0);
}

typedef int (*interface_handler)(int);
struct interface {
    const char* name;
    interface_handler handler;
};
const struct interface avail_interfaces[] = {
    {"READ", interface_read}, 
    {"WRITE", interface_write}, 
    {"IOCTL", interface_ioctl},
};

interface_handler get_interface_by_name(const char* name) {
    for(int i = 0; i < ARRAY_SIZE(avail_interfaces); i++)
        if(!strcasecmp(avail_interfaces[i].name, name))
            return avail_interfaces[i].handler;
    return NULL;
}

/*******************************************************
 * OPTIONS PARSING
 *******************************************************/
struct args {
    int debug;
    const char* output;
    const char* recipe;
    const char* node;
    const char* interface;
    int (*handler)(int fd);
};

const char* argp_program_version = "executor 1.0";
static const char argp_doc[] = "executor -- userspace program for interacting with kflat module";
static const char argp_args_doc[] = "RECIPE NODE";
static struct argp_option options[] = {
    {"interface", 'i', "TYPE", 0, "Select interface type (ex. IOCTL, READ)"},
    {"output", 'o', "FILE", 0, "Save kflat image to FILE"},
    {"debug", 'd', 0, 0, "Enable debug logs in kflat module"},
    { 0 }
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct args* options = state->input;

    switch(key) {
        case 'i':
            options->interface = arg;
            options->handler = get_interface_by_name(arg);
            if(options->handler == NULL)
                argp_usage(state);
            break;

        case 'o':
            options->output = arg;
            break;
        
        case 'd':
            options->debug = 1;
            break;
        
        case ARGP_KEY_ARG:
            if(options->recipe == NULL)
                options->recipe = arg;
            else if(options->node == NULL)
                options->node = arg;
            else
                argp_usage(state);
            break;

        case ARGP_KEY_END:
            break;
        
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static struct argp argp = {options, parse_opt, argp_args_doc, argp_doc};


/*******************************************************
 * ENTRY POINT
 *******************************************************/
int main(int argc, char** argv) {
    int fd, ret;
    struct args opts = {0};
    const size_t dump_size = 100 * 1024 * 1024;

    opts.handler = interface_read;

    init_logging();
    ret = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if(ret)
        log_abort("invalid options provided");

    if(opts.recipe == NULL)
        log_abort("you need to specify the ID of target recipe");
    else if(opts.node == NULL)
        log_abort("you need to specify the target file used by recipe");

    fd = open(KFLAT_NODE, O_RDONLY);
    if(fd < 0)
        log_abort("Failed to open %s - %s", KFLAT_NODE, strerror(errno));

    // Initizalize KFLAT
    struct kflat_ioctl_init init = {0};
    init.size = dump_size;
    init.debug_flag = opts.debug;

    ret = ioctl(fd, KFLAT_INIT, &init);
    if(ret)
        log_abort("Failed to IOCTL KFLAT_INIT - %s", strerror(errno));
    log_info("Initialized kflat (IOCTL KFLAT_INIT)");

    // Mmap result memory
    void* area = mmap(0, dump_size, PROT_READ, MAP_SHARED, fd, 0);
    if(area == MAP_FAILED) 
        log_abort("Failed to mmap area memory - %s", strerror(errno));
    log_info("Maped Kflat area memory @ %p\n", area);

    // Enable capture mode
    struct kflat_ioctl_enable enable = {0};
    enable.pid = getpid();
    strcpy(enable.target_name, opts.recipe);
    ret = ioctl(fd, KFLAT_PROC_ENABLE, &enable);
    if(ret)
        log_abort("Failed to IOCTL KFLAT_PROC_ENABLE - %s", strerror(errno));
    log_info("Enabled kflat capture mode (IOCTL KFLAT_PROC_ENABLE)");


    // Invoke instrumented function
    int oflag = O_RDONLY;
    if(opts.handler == interface_write)
        oflag = O_WRONLY;
    int rd_fd = open(opts.node, oflag);
    if(rd_fd < 0) 
        log_abort("Failed to open %s device - %s", opts.node, strerror(errno));

    ret = opts.handler(rd_fd);
    log_info("%s on node %s returned %d - %s", opts.interface, opts.node, ret, strerror(errno));
    close(rd_fd);


    // Cleanup
    struct kflat_ioctl_disable disable = {0};
    ret = ioctl(fd, KFLAT_PROC_DISABLE, &disable);
    if(ret)
        log_abort("Failed to IOCTL KFLAT_PROC_DISABLE - %s", strerror(errno));
    log_info("Disabled kflat capture mode (IOCTL KFLAT_PROC_DISABLE)");

    if(!disable.invoked)
        log_abort("Recipe was not invoked. Check whether you're selected correct operation and device");
    if(disable.error)
        log_abort("Recipe failed with an error: %d", disable.error);

    log_info("Recipe produced %zu bytes of flattened memory", disable.size);
    if(disable.size > dump_size)
        log_abort("Recipe somehow produced image larger than mmaped buffer (kernel bug?)"
                    " - size: %zu; mmap size: %zu", disable.size, dump_size);

    // Save result
    if(opts.output) {
        int save_fd = open(opts.output, O_RDWR | O_CREAT, 0660);
        if(save_fd < 0)
            log_abort("Failed to open %s - %s", opts.output, strerror(errno));
        
        for(int i = 0; i < disable.size; ) {
            ret = write(save_fd, area + i, disable.size - i);
            if(ret == 0) break;
            else if(ret < 0) log_abort("Failed to write %s - %s", opts.output, strerror(errno));
            else i += ret;
        }
        log_info("Saved result to %s", opts.output);
        close(save_fd);
    }

    munmap(area, dump_size);
    close(fd);
    return 0;
}

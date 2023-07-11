/**
 * @file executor.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Tool for dumping kernel structures with kflat from
 *     common kernel interfaces
 * 
 */

#include "kflat_uapi.h"
#include "common.h"

#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
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

int interface_compat_ioctl(char** argv, char** envp) {
    int ret;

    ret = execve("executor_32", argv, envp);
    if(ret && errno == ENOENT)
        log_abort("Failed to locate 'executor_32' binary needed to execute compat_ioctl");
    else
        log_abort("Failed to spawn 32-bit executor app (%d: %s)", errno, strerror(errno));

    return 0;
}

typedef int (*interface_handler)(int);
struct interface {
    const char* name;
    interface_handler handler;
};
const struct interface avail_interfaces[] = {
#ifdef ENV_64
    {"READ", interface_read}, 
    {"SHOW", interface_read},
    {"WRITE", interface_write}, 
    {"STORE", interface_write},
    {"IOCTL", interface_ioctl},
    {"COMPAT_IOCTL", (interface_handler) interface_compat_ioctl},
#else
    {"COMPAT_IOCTL", interface_ioctl},
#endif
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
    int stop_machine;
    int skip_function_body;
    int run_recipe_now;
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
    {"stop_machine", 's', 0, 0, "Execute kflat recipe under kernel's stop_machine mode"},
    {"skip_funcion_body", 'n', 0, 0, "Do not execute target function body after flattening memory"},
    {"run_recipe_now", 'f', 0, 0, "Execute KFLAT recipe directly from IOCTL without attaching to any kernel function"},
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
        
        case 's':
            options->stop_machine = 1;
            break;

        case 'n':
            options->skip_function_body = 1;
            break;

        case 'f':
            options->run_recipe_now = 1;
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
 * SIGNALS HANDLERS
 *******************************************************/
void sigalrm_handler(int signum) {}

void setup_sigalarm(void) {
    int ret;
    struct sigaction act = {0, };
    act.sa_handler = sigalrm_handler;
    
    ret = sigaction(SIGALRM, &act, NULL);
    if(ret)
        log_abort("Failed to set SIGALRM handler with sigaction - %s", strerror(errno));
}

/*******************************************************
 * PERFORMANCE IMPROVEMENTS
 *******************************************************/
static char active_governor[128];

int governor_save_current(void) {
    int fd = open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", O_RDONLY);
    if(fd < 0)
        goto error;

    int ret = read(fd, active_governor, sizeof(active_governor) - 1);
    if(ret < 0) 
        goto error;
    return 0;

error:
    log_error("Failed to read current active CPU governor - %s", strerror(errno));
    return -1;
}

void governor_restore(void) {
    int fd = open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", O_RDWR);
    if(fd < 0)
        goto error;

    int ret = write(fd, active_governor, sizeof(active_governor) - 1);
    if(ret < 0) 
        goto error;
    return;

error:
    log_error("Failed to restore original CPU governor - %s", strerror(errno));
}

int governor_set(const char* name) {
    int fd = open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", O_RDWR);
    if(fd < 0)
        goto error;

    int ret = write(fd, name, strlen(name));
    if(ret < 0) 
        goto error;
    return 0;

error:
    log_error("Failed to set CPU governor to '%s' - %s", name, strerror(errno));
    return -1;
}

/*******************************************************
 * MAIN ROUTINE
 *******************************************************/
int kflat_open(void) {
    int fd;

    fd = open(KFLAT_NODE, O_RDONLY);
    if(fd >= 0)
        return fd;
    
    if(errno == ENOENT) {
        log_error("");
        log_error("[KFLAT device not found]");
        log_error(" Failed to locate kflat device on debugfs. Make sure debugfs");
        log_error(" is mounted and kflat_core.ko module is loaded into the kernel");
        log_error("");
        log_abort("Failed to open kflat device '%s' - %d:%s", KFLAT_NODE, errno, strerror(errno));
    }

    log_abort("Failed to open kflat device %s - %d:%s", KFLAT_NODE, errno, strerror(errno));
}

void kflat_enable(int fd, struct args* opts) {
    int ret;
    struct kflat_ioctl_enable enable = {0, };

    enable.pid = getpid();
    enable.debug_flag = opts->debug;
    enable.use_stop_machine = opts->stop_machine;
    enable.skip_function_body = opts->skip_function_body;
    enable.run_recipe_now = opts->run_recipe_now;
    strncpy(enable.target_name, opts->recipe, sizeof(enable.target_name));

    ret = ioctl(fd, KFLAT_PROC_ENABLE, &enable);

    if(ret && errno == ENOENT) {
        log_error("");
        log_error("[Recipe not found]");
        log_error(" KFLAT failed to locate selected recipe ID. Please make sure");
        log_error(" that the module with desired recipe has been correctly loaded");
        log_error("");
        log_abort("Failed to enable KFLAT capture mode - %d:%s", errno, strerror(errno));
    } else if(ret != 0)
        log_abort("Failed to enable KFLAT capture mode - %d:%s", errno, strerror(errno));
    
    log_info("Enabled kflat capture mode (IOCTL KFLAT_PROC_ENABLE)");
}

int target_open(const char* name, int write) {
    int fd;
    int oflag = O_RDONLY | O_NONBLOCK;

    if(write)
        oflag |= O_WRONLY;

    fd = open(name, oflag);
    if(fd >= 0)
        return fd;

    if(errno == ENOENT) {
        log_error("");
        log_error("[Target node not found]");
        log_error(" Executor failed to open provided device node. Verify that provided");
        log_error(" path is correct and exists on the device");
        log_error("");
    } else if(errno == EPERM) {
        log_error("");
        log_error("[Permission denied]");
        log_error(" Executor was denied permission to the provided device node. Verify");
        log_error(" that current user has neccessary permissions to access it");
        log_error("");
    }

    log_abort("Failed to open target node '%s' - %d:%s", name, errno, strerror(errno));
}

size_t kflat_disable(int fd, size_t dump_size) {
    int ret;
    struct kflat_ioctl_disable disable;

    ret = ioctl(fd, KFLAT_PROC_DISABLE, &disable);
    if(ret)
        log_abort("Failed to IOCTL KFLAT_PROC_DISABLE - %d:%s", errno, strerror(errno));
    log_info("Disabled kflat capture mode (IOCTL KFLAT_PROC_DISABLE)");

    if(disable.error) {
        log_error("");
        log_error("[KFLAT internal error]");
        log_error(" KFLAT flattening engine reported an error while processing selected recipe");
        log_error("");
        log_abort("KFLAT failed with an error: %d [%s]", disable.error, strerror(disable.error));
    }

    if(!disable.invoked) {
        log_error("");
        log_error("[Recipe was not invoked]");
        log_error(" Function instrumented by the selected recipe has not been invoked. Check whether");
        log_error(" correct operation and device are selected");
        log_error("");
        log_abort("Recipe was not invoked");
    }

    log_info("Recipe produced %zu bytes of flattened memory", disable.size);

    if(disable.size > dump_size) {
        log_error("");
        log_error("[KFLAT internal error]");
        log_error(" Recipe somehow produced image larget than mmaped buffer (kernel bug?)");
        log_error("   --> kernel size: %zu; user mmap size: %zu", disable.size, dump_size);
        log_error("");
        log_abort("KFLAT output buffer overflow (kernel bug?)");
    }

    return disable.size;
}


int main(int argc, char** argv, char** envp) {
    int fd, ret, rd_fd;
    size_t output_size;
    struct args opts = {0};
    const size_t dump_size = 100 * 1024 * 1024;

    opts.handler = interface_read;

    init_logging();
    ret = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if(ret)
        log_abort("invalid options provided");

    if(opts.recipe == NULL)
        log_abort("you need to specify the ID of target recipe");
    if(!opts.run_recipe_now && opts.node == NULL)
        log_abort("you need to specify the target file used by recipe");
    
    // In case of interface compat_ioctl we're deploying executor_32 app
    if(opts.handler == (interface_handler) interface_compat_ioctl)
        interface_compat_ioctl(argv, envp);

    fd = kflat_open();

    /*
     * Mmap memory for result
     */
    void* area = mmap(0, dump_size, PROT_READ, MAP_SHARED, fd, 0);
    if(area == MAP_FAILED) 
        log_abort("Failed to mmap area memory - %s", strerror(errno));
    log_info("Maped Kflat area memory @ %p", area);

    /*
     * Setup CPU frequency scalling for optimal results
     */
    governor_save_current();
    governor_set("performance");
    atexit(governor_restore);

    kflat_enable(fd, &opts);

    if(!opts.run_recipe_now) {
        /*
         * Setup timeout and invoke handler
         */
        setup_sigalarm();
        alarm(2);
        
        rd_fd = target_open(opts.node, opts.handler == interface_write);
        ret = opts.handler(rd_fd);
        log_info("%s on node %s returned %d - %s", opts.interface, opts.node, ret, strerror(errno));
        close(rd_fd);
    }

    output_size = kflat_disable(fd, dump_size);

    /*
     * Save output buffer to file
     */
    if(opts.output) {
        int save_fd = open(opts.output, O_RDWR | O_CREAT, 0660);
        if(save_fd < 0)
            log_abort("Failed to open %s - %s", opts.output, strerror(errno));
        
        for(int i = 0; i < output_size; ) {
            ret = write(save_fd, area + i, output_size - i);
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

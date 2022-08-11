/* 
 * Samsung R&D Poland - Mobile Security Group
 *  Cmdline tool for invoking kflat tests
 */
#include <argp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "kflat_uapi.h"


#define KFLAT_NODE      "/sys/kernel/debug/kflat"

struct args {
    bool list;
    char* test;
    int flags;
    uint64_t selected_tests;
    const char* output_dir;
};

/*******************************************************
 * TESTS AREA
 *******************************************************/
#define KFLAT_TEST_CASE(V)     [V] = {.name = #V, ._v = V }
struct kflat_test_case {
    const char* name;
    int _v;
};

const struct kflat_test_case test_cases[] = {
    KFLAT_TEST_CASE(CIRCLE),
    KFLAT_TEST_CASE(INFO),
    KFLAT_TEST_CASE(STRINGSET),
    KFLAT_TEST_CASE(POINTER),
    KFLAT_TEST_CASE(CURRENTTASK),
    KFLAT_TEST_CASE(SIMPLE),
    KFLAT_TEST_CASE(OVERLAPLIST),
    KFLAT_TEST_CASE(OVERLAPPTR),
    KFLAT_TEST_CASE(STRUCTARRAY),
    KFLAT_TEST_CASE(RPOINTER),
    KFLAT_TEST_CASE(GLOBALCHECK),
    KFLAT_TEST_CASE(PADDING),
    KFLAT_TEST_CASE(GETOBJECTCHECK),
    KFLAT_TEST_CASE(LIST),
    KFLAT_TEST_CASE(LISTHEAD),
    KFLAT_TEST_CASE(HLIST),
    KFLAT_TEST_CASE(LLIST),
    KFLAT_TEST_CASE(HNULLSLIST),
    KFLAT_TEST_CASE(RBNODE),
};

int64_t name_to_test(char* name) {
    if(!strcmp(name, "ALL"))
        return (~0ULL) >> 1;

    for(int i = CIRCLE; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
        if(!strcasecmp(name, test_cases[i].name))
            return 1ULL << (i - 1);
    return -1;
}

void list_tests(void) {
    log_info("Available tests:");
    for(int i = CIRCLE; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
        log_info("\t%2d. \"%s\"", i, test_cases[i].name);
    log_info("Select \"ALL\" to run all of the above tests");
}

int run_test(struct args* args, int no) {
    int ret;
    char out_name[128];
    bool success = false;
    const size_t flat_size = 10 * 1024 * 1024;   // 10MB
    ssize_t output_size;
    
    log_info("starting test %s...", test_cases[no].name);

    int fd = open(KFLAT_NODE, O_RDONLY);
    if(fd < 0) {
        log_error("failed to open %s - %s", KFLAT_NODE, strerror(errno));
        goto exit;
    }

    void* area = mmap(NULL, flat_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(area == MAP_FAILED) {
        log_error("failed to mmap kflat memory - %s", strerror(errno));
        goto close_fd;
    }

    output_size = ioctl(fd, KFLAT_TESTS, KFLAT_TEST_TO_ARG(no, args->flags));
    if(output_size < 0) {
        log_error("failed to execute KFLAT_TEST ioctl - %s", strerror(errno));
        goto munmap_area;
    }

    if(output_size > flat_size)
        log_abort("recipe somehow produced image larger than mmaped buffer (kernel bug?)"
                    " - size: %zu; mmap size: %zu", output_size, flat_size);
    log_info("recipe produced %zu bytes of flattened memory", output_size);

    // Save kflat image
    if(args->output_dir) {
        snprintf(out_name, sizeof(out_name), "%s/flat_%s.img", args->output_dir, test_cases[no].name);

        int save_fd = open(out_name, O_WRONLY | O_CREAT, 0700);
        if(save_fd < 0) {
            log_error("failed to save flatten image to file %s - %s", out_name, strerror(errno));
            goto munmap_area;
        }

        do {
            ret = write(save_fd, area, output_size);
            if(ret > 0)
                output_size -= ret;
        } while(ret > 0);
        if(ret < 0) {
            log_error("failed to write flatten image to file %s - %s", out_name, strerror(errno));
            goto munmap_area;
        }

        close(save_fd);
        log_info("\t  saved flatten image to file %s", out_name);
    }

    if(args->test) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "./%s '%s' '%s'", args->test, out_name, test_cases[no].name);

        log_info("\t ======== imginfo output ========");
        ret = system(cmd);
        log_info("\t ======= end of output(%d) ======", ret);

        if(ret != 0) {
            log_error("imginfo failed with an error: %d", ret);
            goto munmap_area;
        }
    }

    // If we've reached this place, everything went according to plan
    success = true;

munmap_area:
    munmap(area, flat_size);
close_fd:
    close(fd);
exit:
    if(success)
        log_info("\t Test #%d - SUCCESS", no);
    else
        log_info("\t Test %d - FAILED", no);
    return success;
}


/*******************************************************
 * OPTIONS PARSING
 *******************************************************/
const char* argp_program_version = "kflattest 1.0";
static const char argp_doc[] = "kflattest -- test suite for kflat kernel module";
static const char argp_args_doc[] = "TESTS";
static struct argp_option options[] = {
    {"list", 'l', 0, 0, "List available tests"},
    {"output", 'o', "DIR", 0, "Save images to DIR"},
    {"debug", 'd', 0, 0, "Enable kflat debug flag"},
    {"iter", 'i', 0, 0, "Use kflat ITER mode"},
    {"test", 't', "APP", 0, "Execute userspace tester on images"},
    { 0 }
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    int64_t code;
    struct args* options = state->input;

    switch(key) {
        case 'o':
            options->output_dir = arg;
            break;
        case 'l':
            options->list = true;
            break;
        case 'd':
            options->flags |= KFLAT_DEBUG_FLAG;
            break;
        case 'i':
            options->flags |= KFLAT_TEST_ITER;
            break;
        case 't':
            options->test = arg;
            break;
        
        case ARGP_KEY_ARG:
            code = name_to_test(arg);
            if(code < 0) {
                log_error("Incorrect test \"%s\" selected", arg);
                return ARGP_ERR_UNKNOWN;
            }
            options->selected_tests |= code;
            break;
        
        case ARGP_KEY_END:
            if(options->selected_tests == 0 && !options->list)
                argp_usage(state);
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
    int ret;
    struct args opts = {0};
    opts.selected_tests = 0;

    init_logging();
    ret = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if(ret != 0) {
        log_error("invalid options provided");
        exit(1);
    }

    if(opts.list) {
        list_tests();
        return 0;
    }
    if(opts.output_dir) {
        if (mkdir(opts.output_dir, 0770)<0) {
        	if (errno!=EEXIST) {
        		log_info("Could not create directory: %s [error: %s]", opts.output_dir, strerror(errno));
        		exit(1);
        	}
        }
        log_info("will be using %s as output directory", opts.output_dir);
    }
    if(opts.test && !opts.output_dir) {
        log_error("--test option requires output directory to be provided");
        return 1;
    }

    for(int i = CIRCLE; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        if(!(opts.selected_tests & (1ULL << (i-1))))
            continue;

        run_test(&opts, i);
    }

    return 0;
}

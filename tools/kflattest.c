/**
 * @file kflattest.c
 * @author Samsung R&D Poland - Mobile Security Group
 * @brief Cmdline tool for invoking kflat tests
 */

#include <argp.h>
#include <assert.h>
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

#include "../tests/tests_list.h"


#define KFLAT_NODE      "/sys/kernel/debug/kflat"

struct args {
    bool list;
    bool debug;
    bool validate;
    bool verbose;
    const char* output_dir;
};

/*******************************************************
 * TESTS VECTOR
 *  Store the list of test names requested by user
 *******************************************************/
struct tests_list {
    struct tests_list* next;
    const char* name;
} *tests_list_tail;

void add_test_to_list(const char* name) {
    if(tests_list_tail == NULL) {
        tests_list_tail = (struct tests_list*) malloc(sizeof(struct tests_list));
        tests_list_tail->next = NULL;
        tests_list_tail->name = strdup(name);
        return;
    }

    struct tests_list* test = (struct tests_list*) malloc(sizeof(*test));
    test->name = strdup(name);
    test->next = tests_list_tail;
    tests_list_tail = test;
}

bool is_tests_list_empty(void) {
    return tests_list_tail == NULL;
}

/*******************************************************
 * TESTS AREA
 *******************************************************/
static ssize_t get_tests_section(struct kflat_test_case*** tests) {
    size_t tests_count = sizeof(test_cases) / sizeof(test_cases[0]);
    if(tests_count == 0) {
        log_error("kflattest hasn't been compiled with any validator targets");
        *tests = NULL;
        return 0;
    }

    *tests = (struct kflat_test_case **) test_cases;
    return tests_count;
}

void list_tests(void) {
    size_t tests_count;
    struct kflat_test_case** tests;

    tests_count = get_tests_section(&tests);
    if(tests_count == 0)
        return;

    log_info("Available tests [%d]:", tests_count);
    for(size_t i = 0; i < tests_count; i++)
		log_info("\t=> '%s'", tests[i]->name);
}

void add_all_tests(void) {
    size_t tests_count;
    struct kflat_test_case** tests;
    tests_count = get_tests_section(&tests);

    for(size_t i = 0; i < tests_count; i++)
		add_test_to_list(tests[i]->name);
}

kflat_test_case_handler_t get_test_validator(const char* name) {
    size_t tests_count;
    struct kflat_test_case** tests;
    tests_count = get_tests_section(&tests);

	for(size_t i = 0; i < tests_count; i++) {
		if(!strcmp(name, tests[i]->name))
			return tests[i]->handler;
	}

    log_error("No available validator for test named '%s'", name);
	return NULL;
}

int run_test(struct args* args, const char* name) {
    int ret;
    void* area;
    FILE* file;
    char out_name[128];
    bool success = false;
    const size_t flat_size = 10 * 1024 * 1024;   // 10MB
    ssize_t output_size;
    
    struct kflat_ioctl_tests tests = {
        .debug_flag = args->debug
    };

    log_info_continue("Test %s", name);

    int fd = open(KFLAT_NODE, O_RDONLY);
    if(fd < 0) {
        log_error("\rfailed to open %s - %s", KFLAT_NODE, strerror(errno));
        goto exit;
    }

    area = mmap(NULL, flat_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(area == MAP_FAILED) {
        log_error("\rfailed to mmap kflat memory - %s", strerror(errno));
        goto close_fd;
    }

    strncpy(tests.test_name, name, sizeof(tests.test_name));

    output_size = ioctl(fd, KFLAT_TESTS, &tests);
    if(output_size < 0) {
        log_error("\rfailed to execute KFLAT_TEST ioctl - %s", strerror(errno));
        goto munmap_area;
    }

    if(output_size > flat_size)
        log_abort("\rtest somehow produced image larger than mmaped buffer (kernel bug?)"
                    " - size: %zu; mmap size: %zu", output_size, flat_size);
    if(args->verbose)
        log_info("\n\t test produced %zu bytes of flattened memory", output_size);

    // Save kflat image
    if(args->output_dir) {
        snprintf(out_name, sizeof(out_name), "%s/flat_%s.img", args->output_dir, name);

        int save_fd = open(out_name, O_WRONLY | O_CREAT, 0700);
        if(save_fd < 0) {
            log_error("failed to save flatten image to file %s - %s", out_name, strerror(errno));
            goto munmap_area;
        }

        char* offset = (char*)area;
        do {
            ret = write(save_fd, offset, output_size);
            if(ret > 0) {
                output_size -= ret;
                offset += ret;
            }
        } while(ret > 0);
        if(ret < 0) {
            log_error("failed to write flatten image to file %s - %s", out_name, strerror(errno));
            goto munmap_area;
        }

        close(save_fd);
        if(!args->validate || args->verbose)
            log_info("\n\t saved flatten image to file %s", out_name);
    }

    if(args->validate) {
        assert(args->output_dir);

        kflat_test_case_handler_t validator = get_test_validator(name);
        if(validator == NULL)
            goto munmap_area;

        file = fopen(out_name, "rb");
        assert(file != NULL);

        CFlatten flatten = flatten_init(0);
        ret = flatten_load(flatten, file, NULL);
        if(ret != 0) {
            log_error("\rfailed to parse flattened image - %d", ret);
            flatten_deinit(flatten);
            goto munmap_area;
        }

        void* memory = flatten_root_pointer_seq(flatten, 0);
        if(memory == NULL) {
            log_error("\rfailed to acquire first root pointer from image");
            flatten_deinit(flatten);
            goto munmap_area;
        }

        ret = validator(memory, 0, flatten);
        flatten_deinit(flatten);
        if(ret != 0) {
            log_error("\rvalidator returned an error - %d", ret);
            goto munmap_area;
        }

        if(args->verbose)
            log_info("\t\t=> validator accepted result");
    }

    // If we've reached this place, everything went according to plan
    success = true;

munmap_area:
    munmap(area, flat_size);
close_fd:
    close(fd);
exit:
    printf("\r");
    if(success)
        log_info("Test %-30s - SUCCESS", name);
    else
        log_error("Test %-30s - FAILED", name);
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
    {"check", 'c', 0, 0, "Parse and validate saved image"},
    {"verbose", 'v', 0, 0, "More verbose logs"},
    { 0 }
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    int64_t code;
    struct args* options = (struct args*) state->input;

    switch(key) {
        case 'o':
            options->output_dir = arg;
            break;
        case 'l':
            options->list = true;
            break;
        case 'd':
            options->debug = true;
            break;
        case 'c':
            options->validate = true;
            break;
        case 'v':
            options->verbose = true;
        
        case ARGP_KEY_ARG:
            if(!strcmp(arg, "ALL"))
                add_all_tests();
            else
                add_test_to_list(arg);
            break;
        
        case ARGP_KEY_END:
            if(is_tests_list_empty() && !options->list)
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
    int count = 0, success = 0;
    struct args opts = {0};

    init_logging();
    ret = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if(ret != 0) {
        log_error("invalid options provided");
        return 1;
    }

    if(opts.validate && !opts.output_dir) {
        log_error("--check flag requires also --output to be set");
        return 1;
    }

    if(opts.list) {
        list_tests();
        return 0;
    }

    if(opts.output_dir) {
        if (mkdir(opts.output_dir, 0770) < 0) {
        	if (errno != EEXIST) {
        		log_error("Could not create directory: %s [error: %s]", opts.output_dir, strerror(errno));
        		return 1;
        	}
        }
        log_info("Will use `%s` as output directory", opts.output_dir);
    }

    // Execute all tests requested by user
    struct tests_list* el = tests_list_tail;
    while(el) {
        success += !!run_test(&opts, el->name);
        el = el->next;
        count++;
    }

    if(count > 1) {
        log_info("Summary: %d/%d tests succeeded", success, count);
        if(success < count)
            log_error("%d tests FAILED", count - success);
    }

    return 0;
}

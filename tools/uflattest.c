/**
 * @file uflattest.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Cmdline tool for invoking userspace UFLAT tests
 */

#include <argp.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#include "uflat.h"

#include "uflat_tests_list.h"
#include "common_tools.h"

struct args {
    bool list;
    bool debug;
    bool validate;
    bool imginfo;
    bool continuous;
    bool verbose;
    bool skip_memcpy;
    const char* output_dir;
};

int enable_verbose = 0;
static const char* current_test_name = NULL;

/*******************************************************
 * SIGNAL HANDLER
 *  Print neat and readable information for user when
 *  an error occurs
 *******************************************************/
char _last_assert_tested[MAX_LAST_ASSERT];

static void signal_handler(int signo, siginfo_t* si, void* raw_ucontext) {
    // ucontext_t* ucontext = (ucontext_t*) raw_ucontext;

    printf("\n=======================\n");
    log_error("SIGNAL %s", strsignal(signo));
    log_error(" * Failed test: %s", current_test_name ?: "unknown");
    // log_error(" * PC = %lx", ucontext->uc_mcontext.gregs[REG_RIP]);

    switch(signo) {
    case SIGSEGV:
    case SIGILL:
    case SIGBUS:
    case SIGFPE:
        log_error(" * Problematic address = 0x%llx", si->si_addr);
        break;
    }

    log_error(" * Last assertion tested: `%s`", _last_assert_tested);
    log_error("Terminating test...\n");
    fflush(stdout);

    exit(signo);
}

/*******************************************************
 * TESTS VECTOR
 *  Store the list of test names requested by user
 *******************************************************/
struct tests_list {
    struct tests_list* next;
    const char* name;
} * tests_list_tail;

void add_test_to_list(const char* name) {
    if(tests_list_tail == NULL) {
        tests_list_tail = (struct tests_list*)malloc(sizeof(struct tests_list));
        tests_list_tail->next = NULL;
        tests_list_tail->name = strdup(name);
        return;
    }

    struct tests_list* test = (struct tests_list*)malloc(sizeof(*test));
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

    *tests = (struct kflat_test_case**)test_cases;
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

flat_test_case_handler_t get_test_handler(const char* name) {
    size_t tests_count;
    struct kflat_test_case** tests;
    tests_count = get_tests_section(&tests);

    for(size_t i = 0; i < tests_count; i++) {
        if(!strcmp(name, tests[i]->name))
            return tests[i]->handler;
    }

    log_error("No available handler for test named '%s'", name);
    return NULL;
}

flat_test_case_validator_t get_test_validator(const char* name) {
    size_t tests_count;
    struct kflat_test_case** tests;
    tests_count = get_tests_section(&tests);

    for(size_t i = 0; i < tests_count; i++) {
        if(!strcmp(name, tests[i]->name))
            return tests[i]->validator;
    }

    log_error("No available validator for test named '%s'", name);
    return NULL;
}

get_function_address_t get_test_gfa(const char* name) {
    size_t tests_count;
    struct kflat_test_case** tests;
    tests_count = get_tests_section(&tests);

    for(size_t i = 0; i < tests_count; i++) {
        if(!strcmp(name, tests[i]->name))
            return tests[i]->gfa;
    }
    return NULL;
}

enum flat_test_flags get_test_flags(const char* name) {
    size_t tests_count;
    struct kflat_test_case** tests;
    tests_count = get_tests_section(&tests);

    for(size_t i = 0; i < tests_count; i++) {
        if(!strcmp(name, tests[i]->name))
            return tests[i]->flags;
    }
    return 0;
}

int run_test(struct args* args, const char* name) {
    int ret;
    FILE* file;
    char out_name[128];
    int test_result = KFLAT_TEST_FAIL;
    struct time_elapsed total_time, flatten_time;

    if(args->verbose)
        log_info("=> Testing %s...", name);
    current_test_name = name;
    memset(_last_assert_tested, 0, sizeof(_last_assert_tested));

    mark_time_start(&total_time);
    mark_time_start(&flatten_time);

    snprintf(out_name, sizeof(out_name), "%s/flat_%s.img", args->output_dir, name);

    // Setup UFLAT and run test
    struct uflat* uflat = uflat_init(out_name);
    if(UFLAT_PTR_ERR(uflat)) {
        log_error("failed to initialize UFLAT: %s", strerror(UFLAT_PTR_ERR(uflat)));
        goto exit;
    }

    if(args->debug)
        uflat_set_option(uflat, UFLAT_OPT_DEBUG, 1);
    if(args->verbose)
        uflat_set_option(uflat, UFLAT_OPT_VERBOSE, 1);
    if(args->skip_memcpy)
        uflat_set_option(uflat, UFLAT_OPT_SKIP_MEM_COPY, 1);

    flat_test_case_handler_t handler = get_test_handler(name);
    if(handler == NULL) {
        log_error("failed to locate test handler");
        uflat_fini(uflat);
        goto exit;
    }

    ret = handler(&uflat->flat);
    if(ret) {
        log_error("test handler failed");
        uflat_fini(uflat);
        goto exit;
    }

    uflat_fini(uflat);

    if(!args->validate || args->verbose)
        log_info("\t saved flatten image to file %s", out_name);

    mark_time_end(&flatten_time);

    if(args->validate) {
        assert(args->output_dir);

        flat_test_case_validator_t validator = get_test_validator(name);
        if(validator == NULL)
            goto exit;

        file = fopen(out_name, "r+b");
        assert(file != NULL);

        CUnflatten flatten = unflatten_init(0);

        if(args->imginfo) {
            ret = unflatten_imginfo(flatten, file);
            if(ret != 0) {
                log_error("failed to parse flattened image - %s", unflatten_explain_status(ret));
                goto exit;
            }
            rewind(file);
        }

        if(args->continuous || get_test_flags(name) & KFLAT_TEST_FORCE_CONTINOUS) {
            ret = unflatten_load_continuous(flatten, file, get_test_gfa(name));
        } else {
            ret = unflatten_load(flatten, file, get_test_gfa(name));
        }
        if(ret != 0) {
            log_error("failed to parse flattened image - %s", unflatten_explain_status(ret));
            goto unflatten_cleanup;
        }

        void* memory = unflatten_root_pointer_seq(flatten, 0);
        if(memory == NULL) {
            log_error("failed to acquire first root pointer from image");
            goto unflatten_cleanup;
        }

        fflush(stdout);
        fflush(stderr);
        pid_t pid = fork();
        if(pid == 0) {
            ret = validator(memory, 0, flatten);
            exit(ret);
        } else if(pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);

            test_result = WEXITSTATUS(status);
        } else {
            log_error("failed to fork subprocess");
            ret = -1;
            goto unflatten_cleanup;
        }

        switch(test_result) {
        case KFLAT_TEST_SUCCESS:
            if(args->verbose)
                log_info("\t\t=>validator accepted test result");
            break;

        case KFLAT_TEST_UNSUPPORTED:
            if(args->verbose)
                log_info("\t\t=>this test case is unsupported on current platform/build");
            break;

        case KFLAT_TEST_FAIL:
        default:
            if(args->verbose)
                log_error("\t\t=>validator rejected test result - %d", ret);
            break;
        }

    unflatten_cleanup:
        unflatten_deinit(flatten);
        goto exit;
    }

    // If we've reached that place, everything went accordingly to plan
    test_result = KFLAT_TEST_SUCCESS;

exit:

    mark_time_end(&total_time);
    if(args->verbose)
        log_info("\t=> Time spent: flatten [%d.%03ds]; total[%d.%03ds]",
                 flatten_time.seconds, flatten_time.mseconds, total_time.seconds, total_time.mseconds);

    if(test_result == KFLAT_TEST_SUCCESS)
        log_info("Test %-50s [%d.%03ds] - SUCCESS", name, total_time.seconds, total_time.mseconds);
    else if(test_result == KFLAT_TEST_UNSUPPORTED)
        log_info("Test %-50s [%d.%03ds] - %sUNSUPPORTED%s", name,
                 total_time.seconds, total_time.mseconds,
                 OUTPUT_COLOR(LOG_WARN_COLOR), OUTPUT_COLOR(LOG_DEFAULT_COLOR));
    else
        log_error("Test %-50s [%d.%03ds] - %sFAILED%s", name,
                  total_time.seconds, total_time.mseconds,
                  OUTPUT_COLOR(LOG_ERR_COLOR), OUTPUT_COLOR(LOG_DEFAULT_COLOR));
    return test_result == KFLAT_TEST_SUCCESS || test_result == KFLAT_TEST_UNSUPPORTED;
}

/*******************************************************
 * OPTIONS PARSING
 *******************************************************/
const char* argp_program_version = "uflattest 1.0";
static const char argp_doc[] = "uflattest -- test suite for UFLAT library";
static const char argp_args_doc[] = "TESTS";
static struct argp_option options[] = {
    {"list", 'l', 0, 0, "List available tests"},
    {"output", 'o', "DIR", 0, "Save images to DIR"},
    {"debug", 'd', 0, 0, "Enable uflat debug flag"},
    {"skip-check", 's', 0, 0, "Skip saved image validation"},
    {"image-info", 'i', 0, 0, "Print image information before validation"},
    {"continuous", 'c', 0, 0, "Load memory image in continuous fashion during validation"},
    {"verbose", 'v', 0, 0, "More verbose logs"},
    {"single-buffer", 'b', 0, 0, "Don't copy memory to temporary buffer during flattening"},
    {0},
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct args* options = (struct args*)state->input;

    switch(key) {
    case 'o':
        options->output_dir = arg;
        break;
    case 'l':
        options->list = true;
        break;
    case 'i':
        options->imginfo = true;
        break;
    case 'c':
        options->continuous = true;
        break;
    case 'd':
        options->debug = true;
        break;
    case 's':
        options->validate = false;
        break;
    case 'v':
        options->verbose = true;
        break;
    case 'b':
        options->skip_memcpy = true;
        break;

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
    opts.validate = true;

    init_logging();
    ret = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if(ret != 0) {
        log_error("invalid options provided");
        return 1;
    }
    enable_verbose = opts.verbose;

    if(opts.validate && !opts.output_dir)
        opts.output_dir = ".out_tmp";

    if(opts.list) {
        list_tests();
        return 0;
    }

    if(opts.output_dir) {
        if(mkdir(opts.output_dir, 0770) < 0) {
            if(errno != EEXIST) {
                log_error("Could not create directory: %s [error: %s]", opts.output_dir, strerror(errno));
                return 1;
            }
        }
        log_info("Will use `%s` as output directory", opts.output_dir);
    }

    // Setup signal handler
    struct sigaction sig_intercept = {
        .sa_sigaction = signal_handler,
        .sa_flags = SA_SIGINFO,
    };

    sigaction(SIGSEGV, &sig_intercept, NULL);
    sigaction(SIGBUS, &sig_intercept, NULL);
    sigaction(SIGFPE, &sig_intercept, NULL);
    sigaction(SIGILL, &sig_intercept, NULL);
    sigaction(SIGABRT, &sig_intercept, NULL);

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
            log_error("%d tests %sFAILED%s", count - success,
                      OUTPUT_COLOR(LOG_ERR_COLOR), OUTPUT_COLOR(LOG_DEFAULT_COLOR));
        else
            log_info("All tests %spassed%s",
                     OUTPUT_COLOR(LOG_INFO_COLOR), OUTPUT_COLOR(LOG_DEFAULT_COLOR));
    }

    return count - success;
}

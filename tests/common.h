/**
 * @file common.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Common include header for all KFLAT & UFLAT tests. Sections
 *  marked __TESTER__ performs flattening of sample data, while sections
 *  __VALIDATOR__ restores and checks memory.
 * 
 */
#ifndef _LINUX_KFLAT_COMMON_H
#define _LINUX_KFLAT_COMMON_H

/********************************
 * INCLUDES AND TYPES
 ********************************/

/********************************/
#ifdef __TESTER__
/********************************/

#ifdef FLATTEN_KERNEL_BSP
#include <kflat.h>

#define FLATTEN_SETUP_TEST(FLAT)    \
                        struct kflat* kflat = container_of(flat, struct kflat, flat)

#elif defined(FLATTEN_USERSPACE_BSP)
#include <uflat.h>

#define FLATTEN_SETUP_TEST(FLAT)    \
                        struct uflat* uflat = container_of(flat, struct uflat, flat)
#define PAGE_SIZE       (4096)

#else
#error "No BSP config provided"

#endif /* FLATTEN_KERNEL_BSP */

// Stubs for __TESTER__ purpose
#ifndef __VALIDATOR__
typedef void* CUnflatten;
typedef uintptr_t (*get_function_address_t)(const char* fsym);
#endif /* __VALIDATOR__ */

#endif /* __TESTER__ */
/********************************/
#ifdef __VALIDATOR__
/********************************/

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <unflatten.hpp>

enum {
    KFLAT_TEST_SUCCESS  =   0,
    KFLAT_TEST_FAIL,
    KFLAT_TEST_UNSUPPORTED,
};

#ifndef container_of
#define container_of(ptr, type, member) ({			\
  	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})

#endif /* container_of */

extern int enable_verbose;

// Store text of last tested assertion. Used when app ends with sigsegv
//  to indicated what was tested last
#define MAX_LAST_ASSERT 4096
extern char _last_assert_tested[MAX_LAST_ASSERT];

// Fails test when EXPR == false
#define ASSERT(EXPR)    do {                                                    \
                            snprintf(_last_assert_tested, MAX_LAST_ASSERT,      \
                                "[%s:%d] `%s`", __FILE__, __LINE__, #EXPR);     \
                            if(!(EXPR)) {                                       \
                                fprintf(stderr, "=> Test failed: %s\n", _last_assert_tested);   \
                                return KFLAT_TEST_FAIL;                         \
                            }                                                   \
                        } while(0)

// Fails test when A != B
#define ASSERT_EQ(A, B) do {                                                    \
                            snprintf(_last_assert_tested, MAX_LAST_ASSERT,      \
                                "[%s:%d] `%s` == `%s` (0x%llx == 0x%llx)",      \
                                __FILE__, __LINE__, #A, #B, (long long)(A), (long long)(B)); \
                            if((A) != (B)) {                                    \
                                fprintf(stderr, "=> Test failed: %s\n", _last_assert_tested);   \
                                return 1;                                       \
                            }                                                   \
                        } while(0)

// Prints debug message only when kflattest has been started with `-v` flag
#define PRINT(FMT, ...)                                         \
                        if(enable_verbose)                      \
                            printf("\t##" FMT "\n", ##__VA_ARGS__)

#ifndef __TESTER__
struct flat;
#endif /* __TESTER__ */

/********************************/
#endif
/********************************/


typedef int (*flat_test_case_handler_t)(struct flat* flat);
typedef int (*flat_test_case_validator_t)(void* memory, size_t size, CUnflatten flatten);

enum flat_test_flags {
    KFLAT_TEST_ATOMIC           = 1 << 1,
    KFLAT_TEST_FORCE_CONTINOUS  = 1 << 2,
};

struct kflat_test_case {
    const char* name;
    flat_test_case_handler_t handler;
    flat_test_case_validator_t validator;
    enum flat_test_flags flags;
    get_function_address_t gfa;
};

/********************************
 * TESTS REGISTRATION MACRO
 ********************************/

/********************************/
#if defined(__TESTER__) && defined (__VALIDATOR__)
/********************************/

#define KFLAT_REGISTER_TEST_GFA_FLAGS(NAME, FUNC, FUNC_USER, GFA, FLAGS) \
    const struct kflat_test_case test_case_ ## FUNC             \
        __attribute__((used))                                   \
        = {                                                     \
            .name = NAME,                                       \
            .handler = FUNC,                                    \
            .flags = FLAGS,                                     \
            .gfa = GFA,                                         \
            .validator = FUNC_USER                              \
        }

#define KFLAT_REGISTER_TEST_FLAGS(NAME, FUNC, FUNC_USER, FLAGS) \
    KFLAT_REGISTER_TEST_GFA_FLAGS(NAME, FUNC, FUNC_USER, NULL, FLAGS)

#define KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)              \
    KFLAT_REGISTER_TEST_FLAGS(NAME, FUNC, FUNC_USER, 0)

#define KFLAT_REGISTER_TEST_GFA(NAME, FUNC, FUNC_USER, GFA)     \
    KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)


/********************************/
#elif defined(__TESTER__) /* __VALIDATOR__ */
/********************************/

#define KFLAT_REGISTER_TEST_FLAGS(NAME, FUNC, FUNC_USER, FLAGS) \
    const struct kflat_test_case test_case_ ## FUNC             \
        __attribute__((used))                                   \
        = {                                                     \
            .name = NAME,                                       \
            .handler = FUNC,                                    \
            .flags = FLAGS,                                     \
            .gfa = 0,                                           \
            .validator = NULL                                   \
        }

#define KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)              \
    KFLAT_REGISTER_TEST_FLAGS(NAME, FUNC, FUNC_USER, 0)

#define KFLAT_REGISTER_TEST_GFA(NAME, FUNC, FUNC_USER, GFA)     \
    KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)

#define KFLAT_REGISTER_TEST_GFA_FLAGS(NAME, FUNC, FUNC_USER, GFA, FLAGS) \
    KFLAT_REGISTER_TEST_FLAGS(NAME, FUNC, FUNC_USER, 0)

/********************************/
#elif defined(__VALIDATOR__)
/********************************/

#define KFLAT_REGISTER_TEST_GFA(NAME, FUNC, FUNC_USER, GFA)     \
    const struct kflat_test_case test_case_ ## FUNC             \
        __attribute__((used))                                   \
        = {                                                     \
            .name = NAME,                                       \
            .handler = NULL,                                    \
            .gfa = GFA,                                         \
            .validator = FUNC_USER,                             \
            .flags = 0,                                         \
        }

#define KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)              \
    KFLAT_REGISTER_TEST_GFA(NAME, FUNC, FUNC_USER, NULL)

#define KFLAT_REGISTER_TEST_GFA_FLAGS(NAME, FUNC, FUNC_USER, GFA, FLAGS)    \
    KFLAT_REGISTER_TEST_GFA(NAME, FUNC, FUNC_USER, GFA)

#define KFLAT_REGISTER_TEST_FLAGS(NAME, FUNC, FUNC_USER, FLAGS) \
    KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)

/********************************/
#else
#error "Neither __VALIDATOR__ nor __TESTER__ macro is set"

#endif
/********************************/

#endif  /*_LINUX_KFLAT_COMMON_H */

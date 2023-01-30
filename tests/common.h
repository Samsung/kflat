/**
 * @file common.h
 * @author Samsung R&D Poland - Mobile Security Group
 * @brief Common include header for all KFLAT tests. Section under
 *  __KERNEL__ ifdef is compiled for kernel module and the other one
 *  for userspace tests app
 * 
 */
#ifndef _LINUX_KFLAT_COMMON_H
#define _LINUX_KFLAT_COMMON_H

/********************************
 * INCLUDES AND TYPES
 ********************************/

/********************************/
#ifdef __KERNEL__
/********************************/

#include <kflat.h>

#include <linux/interval_tree_generic.h>
#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

INTERVAL_TREE_DEFINE(struct flat_node, rb,
		     uintptr_t, __subtree_last,
		     START, LAST,static __used,interval_tree)


typedef int (*kflat_test_case_handler_t)(struct kflat* kflat);

struct kflat_test_case {
    const char* name;
    kflat_test_case_handler_t handler;
};

/********************************/
#else
/********************************/

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <unflatten.hpp>

typedef int (*kflat_test_case_handler_t)(void* memory, size_t size, CFlatten flatten);

struct kflat_test_case {
    const char* name;
    kflat_test_case_handler_t handler;
    get_function_address_t gfa;
};

enum {
    KFLAT_TEST_SUCCESS  =   0,
    KFLAT_TEST_FAIL,
    KFLAT_TEST_UNSUPPORTED,
};

#define container_of(ptr, type, member) ({			\
  	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})


extern int enable_verbose;

// Store text of last tested assertion. Used when app ends with sigsegv
//  to indicated what was tested last
#define MAX_LAST_ASSERT 4096
extern char _last_assert_tested[MAX_LAST_ASSERT];

// Fails test when EXPR == false
#define ASSERT(EXPR)    do {                                                    \
                            snprintf(_last_assert_tested, MAX_LAST_ASSERT,      \
                                "=> %s:%d: Test failed `%s`", __FILE__, __LINE__, #EXPR); \
                            if(!(EXPR)) {                                       \
                                fprintf(stderr, "%s\n", _last_assert_tested);   \
                                return KFLAT_TEST_FAIL;                         \
                            }                                                   \
                        } while(0)

// Fails test when A != B
#define ASSERT_EQ(A, B) do {                                                    \
                            snprintf(_last_assert_tested, MAX_LAST_ASSERT,      \
                                "=> %s:%d: Test failed `%s` == `%s` (0x%llx != 0x%llx)",    \
                                __FILE__, __LINE__, #A, #B, (long long)(A), (long long)(B)); \
                            if((A) != (B)) {                                    \
                                fprintf(stderr, "%s\n", _last_assert_tested);   \
                                return 1;                                       \
                            }                                                   \
                        } while(0)

// Prints debug message only when kflattest has been started with `-v` flag
#define PRINT(FMT, ...)                                         \
                        if(enable_verbose)                      \
                            printf("\t##" FMT "\n", ##__VA_ARGS__)

/********************************/
#endif
/********************************/


/********************************
 * TESTS REGISTRATION MACRO
 ********************************/

/********************************/
#ifdef __KERNEL__
/********************************/

#define KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)              \
    const struct kflat_test_case test_case_ ## FUNC             \
        __attribute__((used))                                   \
        = {                                                     \
            .name = NAME,                                       \
            .handler = FUNC,                                    \
        }

#define KFLAT_REGISTER_TEST_GFA(NAME, FUNC, FUNC_USER, GFA)     \
    KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)

/********************************/
#else
/********************************/

#define KFLAT_REGISTER_TEST_GFA(NAME, FUNC, FUNC_USER, GFA)     \
    const struct kflat_test_case test_case_ ## FUNC             \
        __attribute__((used))                                   \
        = {                                                     \
            .name = NAME,                                       \
            .handler = FUNC_USER,                               \
            .gfa = GFA,                                         \
        }

#define KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)              \
    KFLAT_REGISTER_TEST_GFA(NAME, FUNC, FUNC_USER, NULL)

/********************************/
#endif
/********************************/

#endif  /*_LINUX_KFLAT_COMMON_H */

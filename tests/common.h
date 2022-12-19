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
#ifdef __KERNEL__

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

#else

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <unflatten.hpp>

typedef int (*kflat_test_case_handler_t)(void* memory, size_t size, CFlatten flatten);

struct kflat_test_case {
    const char* name;
    kflat_test_case_handler_t handler;
};

#define container_of(ptr, type, member) ({			\
  	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
  	(type *)( (char *)__mptr - offsetof(type,member) );})

#define ASSERT(EXPR)    do {                                                \
                            if(!(EXPR)) {                                   \
                                printf("\r=> %s:%d %s: Test failed `%s`\n", __FILE__, __LINE__, __func__, #EXPR); \
                                return 1;                                   \
                            }                                               \
                        } while(0)

#endif


/********************************
 * TESTS REGISTRATION MACRO
 ********************************/
#ifdef __KERNEL__

#define KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)              \
    const struct kflat_test_case test_case_ ## FUNC             \
        __attribute__((used))                                   \
        = {                                                     \
            .name = NAME,                                       \
            .handler = FUNC,                                    \
        }

#else

#define KFLAT_REGISTER_TEST(NAME, FUNC, FUNC_USER)              \
    const struct kflat_test_case test_case_ ## FUNC             \
        __attribute__((used))                                   \
        = {                                                     \
            .name = NAME,                                       \
            .handler = FUNC_USER,                               \
        }

#endif

#endif  /*_LINUX_KFLAT_COMMON_H */
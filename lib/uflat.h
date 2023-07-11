/**
 * @file uflat.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Userspace FLAT (UFLAT) main header file
 * 
 */

#ifndef UFLAT_H
#define UFLAT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef FLATTEN_USERSPACE_BSP
#define FLATTEN_USERSPACE_BSP
#endif /* FLATTEN_USERSPACE_BSP */

#ifdef __cplusplus
extern "C" {
#endif

// Flatten core engine
#include "flatten.h"

#define UFLAT_DEFAULT_OUTPUT_SIZE (50ULL * 1024 * 1024)

/*********************************
 * Exported types
 *********************************/
struct udump_memory_map;

struct uflat {
    struct flat flat;
    struct udump_memory_map* udump_memory;

    int out_fd;
    unsigned long long out_size;
    char* out_name;
    void* out_mem;
};

enum uflat_options {
    /* Print extra information on stdout */
    UFLAT_OPT_VERBOSE = 0,

    /* Print A LOT OF debug information */
    UFLAT_OPT_DEBUG,

    /* Set the maximum size of target flattened image */
    UFLAT_OPT_OUTPUT_SIZE,

    /* Don't generate memory fragments information (smaller image, but only
       load_continous is supported on such image) */
    UFLAT_OPT_SKIP_MEM_FRAGMENTS,


    UFLAT_OPT_MAX
};

/*********************************
 * Exported functions
 *********************************/

/**
 * @brief Initialize Userspace FLAT (UFLAT) engine
 * 
 * @param path path to the output file
 * @return pointer to struct uflat or NULL in case of an error
 */
struct uflat* uflat_init(const char* path) __attribute__ ((warn_unused_result));

/**
 * @brief Set internal UFLAT option bit (for instance, enable debug mode)
 * 
 * @param uflat pointer to uflat structure
 * @param option one of available uflat options
 * @param value the value to be set for selected option
 * @return
 */
int uflat_set_option(struct uflat* uflat, enum uflat_options option, unsigned long value);

/**
 * @brief Clean-up all resources used by UFLAT
 * 
 * @param uflat pointer to uflat structure
 */
void uflat_fini(struct uflat* uflat);

/**
 * @brief Write flattened image to file
 * 
 * @param uflat pointer to uflat structure
 * @return int 0 on success, error code otherwise
 */
int uflat_write(struct uflat* uflat);

#ifdef __cplusplus
}
#endif


#endif /* UFLAT_H */

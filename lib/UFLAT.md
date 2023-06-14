# UFLAT: userspace flattening engine

UFLAT (short for Userspace Flattening) is an userspace port of KFLAT, capable of
performing memory dumps from running userspace C applications. It is built upon the 
same flattening engine as KFLAT making them similar in performance and functionality.

## Building
You can build only `libuflat.so` library (without building tests or Kflat kernel module) with `uflat` target.

```sh
make uflat

# or to cross-compile for other architecture

make ARCH=arm64 uflat
```

## API
Library `libuflat.so` exposes API for C applications.

```c
/**
 * @brief Initialize Userspace FLAT (UFLAT) engine
 * 
 * @param path path to the output file
 * @return pointer to struct uflat or NULL in case of an error
 */
struct uflat* uflat_init(const char* path);

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
```

## Example usage

Below, the most basic use of this library is presented. UFLAT image will be saved to file specified
in `argv[1]` and can be later loaded with `libunflatten.so` library.

```c
#include "uflat.h"

struct uflat* uflat = uflat_init("dst_path.img");
if(uflat == NULL) {
    printf("uflat_init(): failed\n");
    return 1;
}

FOR_ROOT_POINTER(&example_struct,
    FLATTEN_STRUCT(example_struct, &ptr_to_example_struct);
);

int err = uflat_write(uflat);
if (err != 0) {
    printf("flatten_write(): %d\n", err);
    return 1;
}

uflat_fini(uflat);
```

## Copyrights
Just like `libunflatten.so` this library uses code extracted from Linux kernel source tree (files `rbree.c`
and `include_priv/*`) under license GPL-2.0. For details please refer to LICENSE file in the root directory of
this repository.

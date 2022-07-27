# Unflatten: library for recreating kflat images in userspace

Unflatten library allows userspace application to recreate kernel memory layout and data using memory images created by kflat. 

Vast majority of this code is copied from `main.cpp` file present in the original kflat repository.

## API
Library exposes API for both C and C++ applications.

### C++ Interface

```cpp
/*
 * Flatten - construct new (empty) instance of flatten image
 *   (int) level:   debug level used for printing info
 */
Flatten::Flatten(int level = 0);

/*
 * load - load new kflat image from file. This method can be safely
 *  	  called multiple times to load one image after another
 *   (FILE*) file:  pointer to opened file with kflat image
 *   (fptr*) gfa:   optional pointer to function resolving function addresses
 */
Flatten::load(FILE* file, get_function_address_t gfa = NULL);

/*
 * get_next_root - retrieve the pointer to the next flattened object
 */
Flatten::get_next_root();

/*
 * get_seq_root - retrieve the pointer to the n-th flattened object
 *   (size_t) idx:  ID of object to retrieve from image
 */
Flatten::get_seq_root(size_t idx);
```

### C Interface

Flatten library exposes C binding for all available class methods. The usage and arguments are similar to those in C++ interface. Additionally, user must manually release class resources by invoking `flatten_deinit` method.

```c
CFlatten flatten_init(int level);
void flatten_deinit(CFlatten flatten);
int flatten_load(CFlatten flatten, FILE* file, get_function_address_t gfa);
void* flatten_root_pointer_next(CFlatten flatten);
void* flatten_root_pointer_seq(CFlatten flatten, size_t idx);
```

Any exception thrown by underlying C++ code is caught and converted to `-1` or `NULL`, depending on the function return value type.

## Example usage

Below, the most basic use of this library is presented. Kflat image provided as `argv[1]` is loaded into process memory and the content of flattened structure `struct A` is being printed.

```cpp
#include "unflatten.hpp"

int main() {
    Flatten flatten;

    FILE* in = fopen(argv[1], "r");
    assert(in != NULL);

    int ret = flatten.load(in, NULL);
    assert(ret == 0);

    const struct A* pA = (const struct A*) flatten.get_next_root();
    std::cout << pA->x << std::endl;
}
```

## Copyrights
This library uses code extracted from Linux kernel source code (files `rbtree.c` and `include/*`) under license GPL-2.0.

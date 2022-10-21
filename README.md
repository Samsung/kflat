# Kflat: Kernel memory flattening module

**Kflat** is a Linux kernel implementation of the library for fast serialization of C structures. It works by making a copy of the kernel memory for indicated variables and structures. Such copy can be used to recreate the layout of kernel memory in userspace process, for instance in [Auto off-Target](https://github.com/Samsung/auto_off_target) project.

Currently supported architectures are x86_64 and ARM64.

## Building
In order to build kflat framework you're gonna need:
- the source of targeted linux kernel
- the C compiler used to build this kernel
- the C++ compiler for the target architecture - for instance, `aarch64-linux-gnu-g++`

After collecting the above requirements, you can build kflat for your target architecture by using commands below:

**ARM64:**
```sh
export KERNEL_DIR="<path to kernel source>"
export CLANG_DIR="<path to clang directory>"
make KDIR=$KERNEL_DIR CCDIR=$CLANG_DIR ARCH=arm64
```

**x86_64**:
```sh
export KERNEL_DIR="<path to kernel source>"
export CLANG_DIR="<path to clang directory>"
make KDIR=$KERNEL_DIR CCDIR=$CLANG_DIR ARCH=x86_64
```

There are some extra build parameters than can be set to additional options:
- `KFLAT_OPTS` - enable extra/testing features in kflat_core module, like `KFLAT_GET_OBJ_SUPPORT`,
- `KLEE_LIBCXX_INSTALL` - if you wish to build kflat library with support for KLEE symbolic execution engine, specify here the path to libc++ library built for KLEE.

## Project layout

Project directory presents as follow:
```yml
.
├── core            // Main implementation of kflat module
│   └── tests       // Unit-tests
├── doc             // Project documentation
├── include         // Shared include files
├── lib             // Userspace library for unflattening images
│   └── include
├── recipes         // Collection of kflat recipes
│   └── random_read
├── tools           // Userspace tools used with kflat
└── utils           // Miscellaneous utilities
```

## How to use it?

Below you can find general instruction for using kflat kernel module. For more detailed information head out to markdown files in `doc/` directory.

### Load kernel modules
The first step is to upload compiled kernel modules to your target machine. Built modules are located in: `core/kflat_core.ko` and `recipes/*/*.ko` files. To load copied files into the kernel, use `insmod` command:
```sh
insmod kflat_core.ko
insmod kflat_recipe_1.ko
insmod kflat_recipe_2.ko
# ...
```
Keep in mind that `insmod` accepts only a single module at the time - if you provide multiple files in the args list, it will load only the first one and ignore the rest. If loading module fails with error `File exists`, you need to unload currently loaded kflat from the kernel with `rmmod` command (first you need to unload all modules with kflat recipes, before kernel lets you unload the core driver).

In case any other error occurs, please refer to dmesg content, which should describe the source of the issue. If kernel version mismatch is reported, make sure that environment variable `KERNEL_DIR` used during build is set to directory from which kernel running on the target machine has been built.

After successfully loading copied modules with `insmod` command, the file `/sys/kernel/debug/kflat` should appear on debugfs. On newer Android versions, you might need to manually mount debugfs:

```
mount -t debugfs none /sys/kernel/debug
ls /sys/kernel/debug
```

For security reasons, access to this node is restricted only to processes with `CAP_SYS_RAWIO` capability. In case, your application failed to interact with kflat due to `EPERM` (Permission Denied) error, ensure you have the necessary capabilities.

### Run kflat tests
Kflat is equipped with set of basic tests to ensure that all the functionalities are working as expected. In order to run the test, use `./kflattest` app located in `tools/` directory.

```sh
# List all available tests
./kflattest -l

# Run test CIRCLE
./kflattest CIRCLE

# Run all available tests
./kflattest ALL

# Run test CIRCLE and save its output to directory `output`
./kflattest -o output CIRCLE
```

Created memory dumps can be analyzed by using `imginfo` program (formerly called `main.cpp` in original kflat repository). As an arguments, `imginfo` takes the name of test that has been run and memory dump associated with it. Under the hood, the dumped memory is recreated in userspace and processed to determine whether all parts of it were correcly saved and restored.

`kflattest` is capable of executing `imginfo` app on every test result. To use this functionality, simply add `-t ./imginfo` option to cmdline

```sh
# Run test CIRCLE, save its output and print imginfo result
./kflattest -o output -t ./imginfo CIRCLE
```

### Prepare kflat recipe
Kflat requires a description of target memory called _kflat recipe_. Vast and extensive documentation of recipes format is pending. For sample recipes, refer to directory `recipes/`.

Script for automatic generation of such recipes for any given kernel structure is under development. The current revision can be found in `utils/` directory.

### Execute kflat recipe
To execute selected kflat recipe, use `executor` app located in `tools/` directory. The basic usage looks as follow:
```sh
# Run kflat recipe named RANDOM_READ triggered by READing from `/dev/random` and save
#  the dumped memory to file image.kflat
./executor -i READ -o image.kflat RANDOM_READ /dev/random
```

Recipe identifier is the name of function for which assigned recipe will be triggered. IDs are insensitive to case. For details on available program arguments, please refer to `./executor --help`:

### Process kflat image
After executing kflat recipe, dumped slice of kernel memory can be loaded into userspace process address space with help from `Unflatten` library located in `lib/` directory.

Detailed example of how to use Unflatten library can be found in the source code of `imginfo` app. Basic example is also listed below.

```c
#include "unflatten.hpp"

int main(int argc, char** argv) {
    Flatten flatten;

    FILE* in = fopen(argv[1], "r");
    assert(in != NULL);

    assert(flatten.load(in, NULL) == 0);

    const struct A* pA = (const struct A*) flatten.get_next_root();
}
```

Refer to README file in `lib/` directory for details regarding API reference and C bindings usage.


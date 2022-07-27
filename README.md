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

## Project layout

Project directory presents as follow:
```yml
.
├── core            // Main implementation of kflat module
│   └── tests       // Unit-tests
├── include         // Shared include files
├── lib             // Userspace library for unflattening images
│   └── include
├── recipes         // Collection of kflat recipes
│   └── random_read
├── tools           // Userspace tools used with kflat
└── utils           // Miscellaneous utilities
```

## How to use it?

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

## Kernel API

Upon loading, kflat creates a new file on debugfs `/sys/kernel/debug/kflat`, which enables user to interact with loaded module. Allowed file operations on that node are `mmap` and `ioctl`.

### IOCTL commands

Kflat ioctl handlers supports the following commands:

| Command | Details |
| -- | -- |
| KFLAT_INIT | Initializes kflat with provided maximum size of output buffer |
| KFLAT_PROC_ENABLE | Enables selected recipe for process with provided PID |
| KFLAT_PROC_DISABLE | Disables recipe for process with provided PID |
| KFLAT_TESTS | Runs selected kflat unit test |
| KFLAT_MEMORY_MAP | Dumps current kernel memory layout |

Currently, only one recipe can be enabled per one process at the same time. Also, recipes works in single fire mode only - after dumping kflat image, you need to reenable recipe to use it again in the same process.

Example usage of the above commands can be found in `tools/` directory.

### Mmap commands

Kflat mmap handler supports two modes selectable by the value of `offset` argument.
| Offset | Details |
| -- | -- |
| KFLAT_MMAP_FLATTEN _(0)_ | Mmaped memory will contain flattened image of selected structure |
| KFLAT_MMAP_KDUMP _(1)_ | Mmaped memory will be exposing whole kernel-space memory stored in RAM. This feature can be used to conveniently dump kernel memory on devices with `/dev/kmem` disabled. |
| _Other_ | Device will return `-EINVAL` | 

### Example use of kernel API*

The simplified flow of dumping kernel memory with kflat looks as follow:

```c
fd = open("/sys/kernel/debug/kflat", O_RDONLY);

struct kflat_ioctl_init init = {
    .size = 1_MB,       // Output image size
    .debug_flag = 1,    // Whether to output debug logs to dmesg
};
ioctl(fd, KFLAT_INIT, &init);

mem = mmap(NULL, init.size, PROT_READ, MAP_PRIVATE, fd, KFLAT_MMAP_FLATTEN);

struct kflat_ioctl_enable enable = {
    .pid = getpid(),
};
strcpy(enable.target_name, "target_recipe");
ioctl(fd, KFLAT_PROC_ENABLE, &enable);

// Invoke target function
// for instance: fd = open(TARGET_NODE, O_RDONLY); read(fd, buf, sizeof buf);
//  [...]

ioctl(fd, KFLAT_PROC_DISABLE, 0);

// The flattened image is in `mem` array
// [...]

munmap(area, init.size);
```

# Startup guide (Linux)

`kflat` module can be used on any Linux based distribution. In this guide, we'll be focusing on setting it up for Ubuntu based distribution, but you should be able to easily adapt it for any other distro. You might wish to execute this tutorial on virtual machine running Linux OS instead of your host system in case something goes wrong.

## Prerequisities
Start with downloading Linux kernel header files:

```bash
apt install linux-headers
```

Next, download KFLAT repository and simply run `make` to build it for your current kernel using default compiler.
```bash
git clone https://github.com/samsung/kflat && cd kflat
make -j8
```

Once these commands succeed you should end up with `kflat_core.ko` kernel module in `core/` directory.

## Loading KFLAT module
`kflat` exposes `/sys/kernel/debug/kflat` node in debugfs to control flattening operation. First make sure that `debugfs` has been mounted:

```bash
mount -t debugfs none /sys/kernel/debug
```

Next, load compiled kernel module using `insmod` command:

```sh
insmod kflat_core.ko
```

If loading module fails with an error `File exists`, you need to unload currently loaded kflat from the kernel with `rmmod` command. In case any other error occurs, please refer to dmesg content, which should describe the source of the issue. If kernel version mismatch is reported, make sure you've downloaded Linux header files for currently running kernel version.

After successfully loading copied modules with `insmod` command, the file `/sys/kernel/debug/kflat` should appear on debugfs.

```sh
ls /sys/kernel/debug/kflat
```

For security reasons, access to this node is restricted only to processes with `CAP_SYS_RAWIO` capability. In case, your application fails to interact with kflat due to `EPERM` (Permission Denied) error, ensure you have the necessary capabilities (ex. by using `sudo`).

## Running KFLAT tests
Once `kflat` module has been successfully loaded into kernel, you might test it by running a set of basic tests compiled into the module. In order to run the test, use `./kflattest` app located in `tools/` directory.

```sh
# List all available tests
./kflattest -l

# Run test SIMPLE and save its output to directory `output`
./kflattest -o output SIMPLE

# Run all available tests
./kflatest ALL
```

Let's take a look at an implementation of `SIMPLE` test - [HERE](/tests/example_simple.c):
```c
// tests/example_simple.c:19
struct B {
	unsigned char T[4];
};
struct A {
	unsigned long X;
	struct B* pB;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(B);
FUNCTION_DEFINE_FLATTEN_STRUCT(A,
	AGGREGATE_FLATTEN_STRUCT(B, pB);
);

static int kflat_simple_test(struct kflat *kflat) {
	struct B b = { "ABC" };
	struct A a = { 0x0000404F, &b };
	struct A *pA = &a;
	struct A *vpA = (struct A *)0xdeadbeefdabbad00;

	FOR_ROOT_POINTER(pA,
		FLATTEN_STRUCT(A, vpA);
		FLATTEN_STRUCT(A, pA);
	);

	return 0;
}
```

Here we have a `struct A` member which points to another `struct B` object. In order to be able to flatten a structure we have to use `FUNCTION_DEFINE_FLATTEN_STRUCT` macro. This actually creates a function responsible for saving memory image for a given structure object (in case of `struct A` the created function is called `flatten_struct_A`). If structure contains any pointers and we want to include the memory it points to in the final memory image we have to add additional recipe which tells the engine what kind of pointer it is. In our case we have a pointer to another structure therefore we use `AGGREGATE_FLATTEN_STRUCT` recipe. Later we have to point out where the flattening process should start, i.e. we have to use some existing pointer as a root (`FOR_ROOT_POINTER` macro) of the memory image (after the memory is de-serialized we will access the memory image using the same pointer).

Execute the test:
```sh
./tools/kflattest -o out SIMPLE
```

You should see something like:
```
[+][  0.000] main          | Will use `out` as output directory
[+][  0.000] run_test      | => Testing SIMPLE...
[+][  0.216] run_test      |     test produced 164 bytes of flattened memory
[+][  0.216] run_test      |     saved flatten image to file out/flat_SIMPLE.img
[+][  0.211] run_test      | Test SIMPLE - SUCCESS
```

Now, let's execute the same test, but with `-v` (verbose) flag added. With this option, `./kflattest` may print extra information including the content of dumped memory for some test cases. For our simple test, the full command would be:
```bash
./tools/kflattest -v -o out SIMPLE
```

The verification code for our simple case is as follows:
```c
// tests/example_simple.c:40
struct A *pA = (struct A *)memory;

PRINT("struct A = {.X = 0x%08llx, .pB = {%s}}",
			pA->X, pA->pB->T);
```

After executing it we end up with the below output:
```
struct A = {.X = 0x0000404F, .pB = "ABC"}
```

Now stop and ponder for a while what actually happened here. We've had around 20 bytes of memory in the running Linux kernel (additionally part of this memory was a pointer to other place in this memory). We were able to save the memory contents to a file and read it back on different machine, different running Linux version and different process, fix the memory so the embedded pointer points to proper location and verify the memory contents as appropriate. Isn't it awesome?

You can check out the rest of the tests embedded into Kflat to find out about different other features supported by Kflat.

## Creating custom recipe
Testing is good, but our ultimate goal is to dump some useful data from running kernel. To do this we're gonna need to write a special module telling Kflat what and when to dump and what's the layout of flattened memory - so called Kflat recipe. For the purpose of this manual, let's create a flattening recipe for for function `rfkill_fop_write`. The first step is to create directory `rfkill_write` in `recipes/` and file `rfkill_write.c` in there:

```c
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"

// TODO: Copy here the definition of structure rfkill_data

// Declare recipes for required data_types
FUNCTION_DEFINE_FLATTEN_STRUCT(rfkill_data,
);

// Recipe entry point
static void handler(struct kflat* kflat, struct probe_regs* regs) {
    struct rfkill_data* priv = (void*) regs->arg1;

    // Dump structure
    FOR_ROOT_POINTER(rfkill_data,
        FLATTEN_STRUCT(rfkill_data, priv);
    );
}

// Declaration of instrumented functions
KFLAT_RECIPE_LIST(
    KFLAT_RECIPE("rfkill_fop_write", handler)
);
KFLAT_RECIPE_MODULE("KFlat recipe for func rfkill_fop_write");
```

Next, create Kbuild file describing how to build recipe:

```make
obj-m += rfkill_write.o
EXTRA_CFLAGS := -I${PWD}/include/
```

and add module to top-level Kbuild config:

```diff
  obj-m += random_read/
+ obj-m += rfkill_write/
```

Finally, run `make` command in the root directory of this project to generate file `rfkill_write.ko`.

## Executing recipe
Once our custom recipe has been built successfully, we can load it into the running kernel with insmod command:

```sh
insmod recipes/rfkill_write/rfkill_write.ko
```

Finally, to dump kernel memory we need to arm Kflat module and execute targeted syscall. This can be easily achived with `./tools/executor` app. Simply invoke:
```sh
./tools/executor -n -s -o memory.kflat -i WRITE rfkill_write /dev/rfkill
```

The meaning of program arguments is:
- `-n` instructs Kflat to not invoke targetted function (therefore making it safe to do things like `write` on `/dev/sda`),
- `-s` invokes flattening under stop_machine kernel function to avoid data-races
- `-o memory.kflat` specifies the output file
- `-i WRITE` selects syscall to invoke (ex. `READ`, `WRITE`, `IOCTL`)
- `rfkill_write` is the ID of recipe compiled in previous step
- `/dev/rfkill` is a path to the device on which syscall will be invoked

## What's next?
Since we already knew how to write custom recipes and execute them on target OS, next step would be to use Unflatten library (in `lib/` dir) to load generated memory dumps and use them for whatever you might need!

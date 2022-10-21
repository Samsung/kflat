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
`kflat` exposes `/sys/kernel/debug/kflat` node in debugfs to control flattening operation. First make sure that `debugfs` has been propely mounted:
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

For security reasons, access to this node is restricted only to processes with `CAP_SYS_RAWIO` capability. In case, your application failed to interact with kflat due to `EPERM` (Permission Denied) error, ensure you have the necessary capabilities (ex. by using `sudo`).

## Running KFLAT tests
Once `kflat` module has been successfully loaded into kernel, you might test it by running a set of basic tests compiled into the module. In order to run the test, use `./kflattest` app located in `tools/` directory.

```sh
# List all available tests
./kflattest -l

# Run test SIMPLE and save its output to directory `output`
./kflattest -o output SIMPLE
```

Let's take a look at a `SIMPLE` test [test](https://github.com/Samsung/kflat/blob/912e4baa243ee505aaac8e83a5eaa52c4a515929/core/tests/kflat_test.c#L44):
```c
struct B {
	unsigned char T[4];
};
struct A {
	unsigned long X;
	struct B* pB;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(B);

FUNCTION_DEFINE_FLATTEN_STRUCT(A,
    AGGREGATE_FLATTEN_STRUCT(B,pB);
);

static int kflat_simple_test(struct kflat *kflat) {

	int err = 0;
	struct B b = { "ABC" };
	struct A a = { 0x0000404F, &b };
	struct A* pA = &a;
	struct A* vpA = (struct A*) 0xdeadbeefdabbad00;

	flatten_init(kflat);

	FOR_ROOT_POINTER(pA,
		FLATTEN_STRUCT(A, vpA);
		FLATTEN_STRUCT(A, pA);
	);

	flat_infos("@Flatten done: %d\n",kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
	}
	flatten_fini(kflat);

	return err;

}
```

Here we have a `struct A` member which points to another `struct B` object. In order to be able to flatten a structure we have to use `FUNCTION_DEFINE_FLATTEN_STRUCT` macro. This actually creates a function responsible for saving memory image for a given structure object (in case of `struct A` the created function is called `flatten_struct_A`). If structure contains any pointers and we want to include the memory it points to in the final memory image we have to add additional recipe which tells the engine what kind of pointer it is. In our case we have a pointer to another structure therefore we use `AGGREGATE_FLATTEN_STRUCT` recipe. Later we have to point out where the flattening process should start, i.e. we have to use some existing pointer as a root (`FOR_ROOT_POINTER macro`) of the memory image (after the memory is de-serialized we will access the memory image using the same pointer).

Execute the test:
```sh
./tools/kflattest -o out SIMPLE
```

You should see something like:
```
[+][  0.000] main      | will be using out as output directory
[+][  0.000] run_test  | starting test SIMPLE...
[+][  0.084] run_test  | recipe produced 156 bytes of flattened memory
[+][  0.084] run_test  |          saved flatten image to file out/flat_SIMPLE.img
[+][  0.084] run_test  |         Test #5 - SUCCESS
```

Now get back to your `kflat` source directory and check the `kflat` verification suite available [here](https://github.com/Samsung/kflat/blob/912e4baa243ee505aaac8e83a5eaa52c4a515929/tools/imginfo.cpp#L379). It reads the image retrieved from the kernel, establishes the image in the process memory and verifies its correctness. It accepts a test name as a parameter. For our simple test this would be:
```bash
./tools/imginfo out/flat_SIMPLE.img SIMPLE
```

The verification code for our simple case is as follows:
```c
printf("sizeof(struct A): %zu\n", sizeof(struct A));
		printf("sizeof(struct B): %zu\n", sizeof(struct B));
		
		const struct A* pA = (const struct A*) flatten.get_next_root();
		printf("pA->X: %016lx\n" ,pA->X);
		printf("pA->pB->T: [%02x%02x%02x%02x]\n", 
					pA->pB->T[0], pA->pB->T[1], 
					pA->pB->T[2], pA->pB->T[3]);
```

After executing it we end up with the below output:
```
sizeof(struct A): 16
sizeof(struct B): 4
pA->X: 000000000000404f
pA->pB->T: [41424300]
```

Now stop and ponder for a while what actually happened here. We've had around 20 bytes of memory in the running Linux kernel (additionally part of this memory was a pointer to other place in this memory). We were able to save the memory contents to a file and read it back on different machine, different running Linux version and different process, fix the memory so the embedded pointer points to proper location and verify the memory contents as appropriate. Isn't it awesome?

You can check out the rest of the tests embedded into Kflat to find out about different other features supported by Kflat.

## Creating custom recipe
Testing is good, but our ultimate goal is to dump some useful data from running kernel. To do this we're gonna need to write a special module telling Kflat what and when to dump and what's the layout of flattened memory - so called Kflat recipe. Let's start by creating a new directory `TODO` in `recipes/` directory.

```c
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"


// Declare recipes for required data_types
FUNCTION_DEFINE_FLATTEN_STRUCT(priv_data,
	// ...
);

// Recipe entry point
static void handler(struct kflat* kflat, struct probe_regs* regs) {
    struct priv_data* priv = (void*) regs->arg1;

    // Dump structure
    FOR_ROOT_POINTER(priv,
        FLATTEN_STRUCT(priv_data, priv);
    );
}

// Declaration of instrumented functions
KFLAT_RECIPE_LIST(
    KFLAT_RECIPE("<function_name, ex. random_read>", handler)
);
KFLAT_RECIPE_MODULE("First custom Kflat recipe");
```

Create Kbuild file describing how to build recipe:

```make
obj-m += your-c-file-1.o your-c-file-2.o
EXTRA_CFLAGS := -I${PWD}/include/
```

and add module to top-level Kbuild config:

```diff
  obj-m += random_read/
+ obj-m += TODO/
```

Finally, run `make` command in the root directory of this project to generate file `todo_recipe.ko`.

## Executing recipe
Once our custom recipe has been built successfully, we can load it into the running kernel with insmod command:

```sh
insmod recipes/TODO/TODO.ko
```

Finally, to dump kernel memory we need to arm Kflat module and execute targeted syscall. This can be easily achived with `./tools/executor` app. Simply invoke:
```sh
./tools/executor -n -s -o memory.kflat -i READ TODO path_todo
```

The meaning of program arguments is:
- `-n` instructs Kflat to not invoke targetted function (therefore making it safe to do things like `write` on `/dev/sda`),
- `-s` invokes flattening under stop_machine kernel function to avoid data-races
- `-o memory.kflat` specifies the output file
- `-i READ` selects syscall to invoke (ex. `READ`, `WRITE`, `IOCTL`)
- `TODO` is the ID of recipe compiled in previous step
- `path_todo` is a path to the device on which syscall will be invoked

## What's next?
Since we already knew how to write custom recipes and execute them on target OS, next step would be to use Unflatten library (in `lib/` dir) to load generated memory dumps and use them for whatever you might need!

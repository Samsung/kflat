# Startup guide (Android)

First `kflat` implementation was prepared for the Android kernel emulator and tested thereof. To show examples of `kflat` operation first thing to do is to setup the proper Linux development environment. We would need full AOSP source code together with the Linux kernel to compile and test the `kflat` module on the emulator. 


## Prerequisites
### Downloading Android and setting up emulator
Start with defining your source directories:

```bash
export ROOT_DIR=<your_source_root_directory>
export SDK_DIR=<path_to_android_sdk> 
```

Now download latest AOSP source code:
```bash
export ANDROID_DIR=${ROOT_DIR}/android
mkdir -p ${ANDROID_DIR} && cd ${ANDROID_DIR}
repo init -u https://android.googlesource.com/platform/manifest
git --git-dir=.repo/manifests/.git/ branch -a | grep android\-12 # Look for latest branch
repo init -u https://android.googlesource.com/platform/manifest -b android-12.0.0_r15 # At some point this was the latest branch
repo sync -j32
```

If you don't have `repo` you might want to download the launcher from [here](https://source.android.com/setup/develop#installing-repo).

Next download Linux kernel sources for the emulator:
```bash
export KERNEL_DIR=${ROOT_DIR}/kernel
mkdir -p ${KERNEL_DIR} && cd ${KERNEL_DIR}
git clone https://android.googlesource.com/kernel/build build
git clone https://android.googlesource.com/platform/prebuilts/build-tools prebuilts/build-tools
git clone -b android-11.0.0_r28 --single-branch https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/x86/x86_64-linux-android-4.9
git clone https://android.googlesource.com/kernel/prebuilts/build-tools prebuilts/kernel-build-tools
git clone https://android.googlesource.com/kernel/common-modules/virtual-device common-modules/virtual-device
(cd common-modules/virtual-device && git checkout 272a06c7d90c63f756ee998957609c25ebc6a6cf)
git clone https://android.googlesource.com/kernel/common kernel
(cd kernel && git checkout 53a812c6bbf3d88187f5f31a09b5499afc2930fb)
```

Now build the kernel (you would need to install `clang-11` based toolchain (including `ld.lld-11`) to make this example working (or modify this example accordingly)):
```bash
export ARCH=x86_64
export CLANG_TRIPLE=x86_64-linux-gnu-
export CROSS_COMPILE=x86_64-linux-gnu-
export LINUX_GCC_CROSS_COMPILE_PREBUILTS_BIN=${ROOT_DIR}/kernel/x86_64-linux-android-4.9/bin
DEVEXPS="CC=clang-11 LD=ld.lld-11 NM=llvm-nm-11 OBJCOPY=llvm-objcopy-11 DEPMOD=depmod DTC=dtc BRANCH=android12-5.10 LLVM=1 EXTRA_CMDS='' STOP_SHIP_TRACEPRINTK=1 DO_NOT_STRIP_MODULES=1 IN_KERNEL_MODULES=1 KMI_GENERATION=9 HERMETIC_TOOLCHAIN=${HERMETIC_TOOLCHAIN:-1} BUILD_INITRAMFS=1 LZ4_RAMDISK=1 LLVM_IAS=1 BUILD_GOLDFISH_DRIVERS=m BUILD_VIRTIO_WIFI=m BUILD_RTL8821CU=m"
export KBUILD_BUILD_USER=build-user
export KBUILD_BUILD_HOST=build-host
export PATH=$LINUX_GCC_CROSS_COMPILE_PREBUILTS_BIN:$PATH
cd ${KERNEL_DIR}/kernel
make $DEVEXPS mrproper
KCONFIG_CONFIG=$KERNEL_DIR/kernel/.config $KERNEL_DIR/kernel/scripts/kconfig/merge_config.sh -m -r $KERNEL_DIR/kernel/arch/x86/configs/gki_defconfig ${KERNEL_DIR}/common-modules/virtual-device/virtual_device.fragment
${KERNEL_DIR}/kernel/scripts/config --file .config -d LTO -d LTO_CLANG -d LTO_CLANG_FULL -d CFI -d CFI_PERMISSIVE -d CFI_CLANG
make $DEVEXPS olddefconfig
make $DEVEXPS -j32
rm -rf staging && mkdir -p staging
make $DEVEXPS "INSTALL_MOD_STRIP=1" INSTALL_MOD_PATH=$KERNEL_DIR/kernel/staging modules_install
make -C $ROOT_DIR/kernel/common-modules/virtual-device M=../common-modules/virtual-device KERNEL_SRC=$KERNEL_DIR/kernel $DEVEXPS -j32 clean
make -C $ROOT_DIR/kernel/common-modules/virtual-device M=../common-modules/virtual-device KERNEL_SRC=$KERNEL_DIR/kernel $DEVEXPS -j32
make -C $ROOT_DIR/kernel/common-modules/virtual-device M=../common-modules/virtual-device KERNEL_SRC=$KERNEL_DIR/kernel $DEVEXPS -j32 "INSTALL_MOD_STRIP=1" INSTALL_MOD_PATH=$KERNEL_DIR/kernel/staging modules_install
```

Copy built modules to the Android source tree so the AOSP tree will have all the required modules built with the current version of the kernel (Android emulator will not boot when the Linux kernel source tree used to build the prebuilt version of modules do not match the kernel image you're running). 
```bash
find staging/lib/modules/ -name "*.ko" -exec cp '{}' ${ANDROID_DIR}/kernel/prebuilts/common-modules/virtual-device/5.10/x86-64/ \;
```

You can now finally build the Android image:
```bash
cd $ANDROID_DIR
source build/envsetup.sh
lunch sdk_phone64_x86_64
m
```

And run the emulator with the images we've just built:
```bash
export LD_LIBRARY_PATH=${SDK_DIR}/emulator/lib64:${SDK_DIR}/emulator/lib64/gles_swiftshader:${SDK_DIR}/emulator/lib64/gles_angle:${SDK_DIR}/emulator/lib64/gles_angle9:${SDK_DIR}/emulator/lib64/gles_angle11:${SDK_DIR}/emulator/lib64/libstdc++:${SDK_DIR}/emulator/lib64/qt/lib
${SDK_DIR}/emulator/qemu/linux-x86_64/qemu-system-x86_64-headless \
        -netdelay none -netspeed full \
        -verbose \
        -show-kernel \
        -no-snapshot \
        -kernel ${KERNEL_DIR}/kernel/arch/x86/boot/bzImage \
        -data ${ANDROID_DIR}/out/target/product/emulator64_x86_64/userdata.img \
        -ramdisk ${ANDROID_DIR}/out/target/product/emulator64_x86_64/ramdisk-qemu.img \
        -system ${ANDROID_DIR}/out/target/product/emulator64_x86_64/system-qemu.img \
        -vendor ${ANDROID_DIR}/out/target/product/emulator64_x86_64/vendor-qemu.img \
        -sysdir ${ANDROID_DIR}/out/target/product/emulator64_x86_64 \
        -memory 16384
```
The above command will run the emulator without the GUI support (we don't need that for testing purposes, just having working adb will suffice). To run the kernel latest emulator is needed (it was tested on the 30.9.5.0 version of the emulator). On older emulator releases it tends to restart init services without properly setup adb connection.

### Building KFLAT
Now open new window and clone the `kflat` sources:
```bash
git clone https://github.com/samsung/kflat.git && cd kflat
```

and build it for the `x86_64` architecture:
```bash
export CLANG_DIR=${ANDROID_DIR}/prebuilts/clang/host/linux-x86/clang-r416183b
make KDIR=${KERNEL_DIR}/kernel ARCH=x86_64 CCDIR=$CLANG_DIR
```

Now you're ready to rock'n'roll. 

## Running KFLAT tests
`kflat` exposes `/sys/kernel/debug/kflat` node in the debugfs to control flattening operation. First make sure `debugfs` is properly mounted (starting from Android 11 it is not enabled by default even in engineering builds):
```bash
export PATH=$SDK_DIR/platform-tools:$PATH
adb shell mount -t debugfs none /sys/kernel/debug
```

The `kflat` module needs to be loaded on to the device where we operate:
```bash
adb shell mkdir -p /data/local/tmp
adb push core/kflat_core.ko /data/local/tmp 
adb shell insmod /data/local/tmp/kflat_core.ko
```

When this operation succeeds you should see the `kflat` node in the `sysfs`:
```
adb shell ls -la /sys/kernel/debug/kflat
```

Now kflat must be initialized using proper ioctl call on the `/sys/kernel/debug/kflat` node and then memory buffer should be mapped using mmap system call. This buffer will serve as a intermediary buffer between kernel and user space. When flattening operation is triggered inside the kernel on some internal data structure the data will be stored inside this buffer which can be accessed from the user space. Fortunately there are tools which can do all the necessary setup work and run the tests or trigger internal kernel structure flattening operation on a selected entry point.

Let's start with the tests. `kflat` test suite can be found in `tests/` subdirectory. There's also a handy tool to setup and run kflat tests for us on the device:
```bash
adb push tools/kflattest /data/local/tmp
```

Let's start with test `SIMPLE` - available [HERE](/tests/example_simple.c):
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

Here we have a `struct A` member which points to another `struct B` object. In order to be able to flatten a structure we have to use `FUNCTION_DEFINE_FLATTEN_STRUCT` macro. This actually creates a function responsible for saving memory image for a given structure object (in case of `struct A` the created function is called `flatten_struct_A`). If structure contains any pointers and we want to include the memory it points to in the final memory image we have to add additional recipe which tells the engine what kind of pointer it is. In our case we have a pointer to another structure therefore we use `AGGREGATE_FLATTEN_STRUCT` recipe. Later we have to point out where the flattening process should start, i.e. we have to use some existing pointer as a root (`FOR_ROOT_POINTER macro`) of the memory image (after the memory is de-serialized we will access the memory image using the same pointer).

Execute the test:
```bash
adb shell /data/local/tmp/kflattest -o /data/local/tmp SIMPLE
```

You should see something like:
```
[+][  0.000] main          | Will use `out` as output directory
[+][  0.000] run_test      | => Testing SIMPLE...
[+][  0.216] run_test      |     test produced 164 bytes of flattened memory
[+][  0.216] run_test      |     saved flatten image to file /data/local/tmp/flat_SIMPLE.img
[+][  0.211] run_test      | Test SIMPLE - SUCCESS
```

Now, let's execute the same test, but with `-v` (verbose) flag added. With this option, `./kflattest` may print extra information including the content of dumped memory for some test cases. For our simple test, the full command would be:
```bash
adb shell /data/local/tmp/kflattest -v -o out SIMPLE
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

Now stop and ponder for a while what actually happened here. We've had around 20 bytes of memory in the running Linux kernel (additionally part of this memory was a pointer to other place in this memory). We were able to save the memory contents to a file and read it back on different machine, different running Linux version and different process, fix the memory so the embedded pointer points to proper location and verify the memory contents as appropriate.

Let's now check some more advanced test - `example_circle.c`:
```c
struct point {
    double x;
    double y;
    unsigned n;
    struct point** other;
};

struct figure {
    const char* name;
    unsigned n;
    struct point* points;
};

FUNCTION_DEFINE_FLATTEN_STRUCT(point,
    AGGREGATE_FLATTEN_TYPE_ARRAY(struct point*, other, ATTR(n));
    FOREACH_POINTER(struct point*, p, ATTR(other), ATTR(n),
            FLATTEN_STRUCT(point, p);
    );
);

FUNCTION_DEFINE_FLATTEN_STRUCT(figure,
    AGGREGATE_FLATTEN_STRING(name);
    AGGREGATE_FLATTEN_STRUCT_ARRAY(point,points,ATTR(n));
);
```

This test creates a figure (which is actually a circle of radius 1.0) which consists of `n` points (evenly distributed across circumference). Each point apart from its cartesian coordinates also holds an array of pointers to all other points.
```bash
adb shell /data/local/tmp/kflattest -o /data/local/tmp CIRCLE
```

The test makes a circle of 30 points and then dumps the memory area of the circle elements:
```
[+][  0.000] main      | will be using /data/local/tmp as output directory
[+][  0.000] run_test  | starting test CIRCLE...
[+][  0.056] run_test  | recipe produced 15791 bytes of flattened memory
[+][  0.056] run_test  |          saved flatten image to file /data/local/tmp/flat_CIRCLE.img
[+][  0.056] run_test  |         Test #1 - SUCCESS
```

The verification code reads it back and computes some features of our circle, like approximated length of the circumference:
```bash
adb shell adb shell /data/local/tmp/kflattest -v -o /data/local/tmp SIMPLE
```
```
Number of edges/diagonals: 435
Sum of lengths of edges/diagonals: 572.43410063184580849
Half of the circumference: 3.13585389802960446
```

In another `STRINGSET` we have a red-black tree based implementation for a set of C-style strings. We create such set and fill it with randomly generated 50k strings.

```c
struct __attribute__((aligned(sizeof(long)))) rb_node {
    uintptr_t __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
};

struct rb_root {
	struct rb_node *rb_node;
};

struct string_node {
	struct rb_node node;
	char* s;
};

static inline const struct string_node* ptr_remove_color(const struct string_node* ptr) {
	return (const struct string_node*)( (uintptr_t)ptr & ~3 );
}

static inline struct flatten_pointer* fptr_add_color(struct flatten_pointer* fptr, const struct string_node* ptr) {
	fptr->offset |= (size_t)((uintptr_t)ptr & 3);
	return fptr;
}

FUNCTION_DEFINE_FLATTEN_STRUCT(string_node,
	STRUCT_ALIGN(4);
	AGGREGATE_FLATTEN_STRUCT_MIXED_POINTER(string_node,node.__rb_parent_color,ptr_remove_color,fptr_add_color);
	AGGREGATE_FLATTEN_STRUCT(string_node,node.rb_right);
	AGGREGATE_FLATTEN_STRUCT(string_node,node.rb_left);
	AGGREGATE_FLATTEN_STRING(s);
);

FUNCTION_DEFINE_FLATTEN_STRUCT(rb_root,
	AGGREGATE_FLATTEN_STRUCT(string_node,rb_node);
);
```

This example is a little bit more complicated as the `__rb_parent_color` member of `struct rb_node` is actually a pointer (despite the `uintptr_t` type) which holds the node color in its two least significant bits. This requires additional processing to clear and restore the bits while serializing the memory image.

```bash
adb shell /data/local/tmp/kflattest -v -o /data/local/tmp STRINGSET
```

yields:
```
[+][  0.000] main      | will be using /data/local/tmp as output directory
[+][  0.000] run_test  | starting test STRINGSET...
[+][  0.056] run_test  | recipe produced 15791 bytes of flattened memory

stringset size: 50
```


Again, think for a moment what just happened. There was a large data structure inside the kernel, heavily linked using pointers (many data structures inside the kernel is actually based on this red-black tree implementation like handling memory regions with interval trees, process scheduling etc.). Writing 17 lines of code with the recipes allowed us to fully serialize this tree and read it back on host machine impeccably in its entirety.


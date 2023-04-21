# Memory Map Example

This example flattens KFLAT's interval tree storing kernel's virtual memory layout 
consisting of around 400k elements. Once flattened, application `client_app` allows user
to browse through this interval tree and list physicall addresses of maped VA pages.

## Build

This kernel module is build alongside all other files in this repo - simply enter
root directory of KFLAT repository and run `make` command from README.md. After that, there should
be file `memory_map_recipe.ko` present in this directory.

Building userspace test app is a bit more complicated as it has to be done manually. See
below example commands for cross-compiling for ARM64 and for native compiling for x86_64.

```bash
CFLAGS="-I../../include -I../../lib -I../../lib/include_priv --static"

# Target: x86_64
g++ $CFLAGS -o client_app client_app.cpp ../../lib/libunflatten_x86_64.a -lstdc++

# Target: ARM64
aarch64-linux-gnu-g++ $CFLAGS -o client_app client_app.cpp ../../lib/libunflatten_arm64.a -lstdc++
```

## Run

Load `kflat_core.ko` module first. Next, load `memory_map_recipe.ko` module present in this
directory. Finally, execute `./client_app` program to test flattening and display your's
kernel VA memory layout.

```
First few Kernel pages:
        (0xffffff80011d0000-0xffffff80019fffff) => 0x811d0000
        (0xffffff8001f20000-0xffffff80025fffff) => 0x81f20000
        (0xffffff8001cf4000-0xffffff8001cfffff) => 0x81cf4000
        (0xffffff801b09c000-0xffffff801b0fffff) => 0x9b09c000
        (0xffffff8028000000-0xffffff8054cfffff) => 0xa8000000
        (0xffffff80243b4000-0xffffff8027cfffff) => 0xa43b4000
        (0xffffff8002800000-0xffffff800a7fffff) => 0x82800000
        (0xffffff807acc0000-0xffffff807f7fffff) => 0xfacc0000
        (0xffffff8800000000-0xffffff88001fefff) => 0x880000000
        (0xffffff807fe09000-0xffffff807fffffff) => 0xffe09000
        (0xffffff8800900000-0xffffff8800afffff) => 0x880900000
        (0xffffff8840000000-0xffffff897b2f2fff) => 0x8c0000000
        (0xffffff8800b02000-0xffffff883b1fffff) => 0x880b02000
        (0xffffff8800200000-0xffffff88003fffff) => 0x880200000
        (0xffffff8063bb0000-0xffffff80737fffff) => 0xe3bb0000
        (0xffffff897b2f7000-0xffffff897b2f7fff) => 0x9fb2f7000
        (0xffffff897b2fd000-0xffffff897b2fdfff) => 0x9fb2fd000
        (0xffffff897b2f9000-0xffffff897b2f9fff) => 0x9fb2f9000
        (0xffffff897b303000-0xffffff897b303fff) => 0x9fb303000
        (0xffffff897b307000-0xffffff897b307fff) => 0x9fb307000

Looking up physical address of common kernel functions:
         [__kmalloc]: 0xffffffc0086cc2cc ==> 0xa86cc2cc
         [__memcpy]: 0xffffffc0081e7e70 ==> 0xa81e7e70
         [flatten_write]: 0xffffffc003baedf8 ==> 0x926470df8

Total amount of virtual memory allocated: 7871MB
Total amount of physical memory allocated: 7871MB
```

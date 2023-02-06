# Memory Map Example

This example flattens KFLAT's interval tree storing kernel's virtual memory layout 
consiting of around 400k elements. Once flattened, application `client_app` allows user
to browse through this interval tree and list physicall addresses of maped VA pages.

## Build

This kernel module is build alongside all other files in this repo - simply enter
root directory of KFLAT repository and run `make` command from README.md. After that, there should
be file `kflat_core.ko` present in this directory.

Building userspace test app is a bit more complicated as it has to be done manually. See
below example commands for cross-compiling for ARM64 and for native compiling for x86_64.

```bash
CFLAGS="-I../../include -I../../lib -I../../lib/include_priv --static"

# Target: x86_64
gcc $CFLAGS -o client_app client_app.c ../../lib/libunflatten_arm64.a -lstdc++

# Target: ARM64
aarch64-linux-gnu-gcc $CFLAGS -o client_app client_app.c ../../lib/libunflatten_arm64.a -lstdc++
```

## Run

Load `kflat_core.ko` module first. Next, load `mem_map_recipe.ko` module present in this
directory. Finally, execute `./client_app` program to test flattening and display your's
kernel VA memory layout.

```
# TODO: output
```

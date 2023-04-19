# Current task_struct example

This example flattens selected fields from current `task_struct`. Once flattened,
application `task_current_client` allows user to view information about running
processes, including `pid`, `permissions`, etc.

## Build

This kernel module is build alongside all other files in this repo - simply enter root
directory of KFLAT repo and run `make` command as described in README.md. After that,
there should be file `task_current_recipe.ko` present in this directory.

Building userspace test app is a bit more complex as it has to be done manually.

```bash
CFLAGS="-I../../include -I../../lib -I../../lib/include_priv --static"

# Target: x86_64
g++ $CFLAGS -o task_current_client task_current_client.cpp ../../lib/libunflatten_x86_64.a -lstdc++

# Target: ARM64
aarch64-linux-gnu-g++ $CFLAGS -o task_current_client task_current_client.cpp ../../lib/libunflatten_arm64.a -lstdc++
```

## Run

Load modules `kflat_core.ko` and `task_current_recipe.ko`. Next, use tool `tools/executor` to
invoke `random_read` handler.

```bash
$ tools/executor -i READ -o task_struct.bin -s -n random_read /dev/random
```

Finally, execute `./task_current_client <output_file>` app to test flattening and display
information about currently running processes in system.

```
$ ./task_current_client task_struct.bin
Loaded input file ./task_struct.bin
T[21:21], cpu: 0, prio: 0, comm: migration/0
T[2:2], cpu: 2, prio: 120, comm: kthreadd
T[15:15], cpu: 0, prio: 120, comm: rcuog/0
T[44:44], cpu: 0, prio: 120, comm: rcuop/3
T[0:0], cpu: 0, prio: 120, comm: swapper/0
T[1:1], cpu: 1, prio: 120, comm: init
```

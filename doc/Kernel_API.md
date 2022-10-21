# Kernel API

Upon loading, kflat creates a new file on debugfs named `/sys/kernel/debug/kflat`, which enables user to interact with loaded module. Allowed file operations on that node are `mmap`, `read` and `ioctl`.

## IOCTL commands

Kflat ioctl handlers supports the following commands:

| Command | Details |
| -- | -- |
| KFLAT_PROC_ENABLE | Enables selected recipe for process with provided PID |
| KFLAT_PROC_DISABLE | Disables recipe for process with provided PID |
| KFLAT_TESTS | Runs selected kflat unit test |
| KFLAT_MEMORY_MAP | Dumps current kernel memory layout |

Currently, only one recipe can be enabled per one process at the same time. Also, recipes works in single fire mode only - after dumping kflat image, you need to reenable recipe to use it again in the same process. The definition of this IOCTL commands and structures expected by each of them, can be found in file `include/kflat_uapi.h`.

Example usage of the above commands can be found in `executor` app in `tools/` directory.

## Mmap commands

Kflat mmap handler supports two modes selectable by the value of `offset` argument.
| Offset | Details |
| -- | -- |
| KFLAT_MMAP_FLATTEN _(0)_ | Mmaped memory will contain flattened image of selected structure |
| KFLAT_MMAP_KDUMP _(1)_ | Mmaped memory will be exposing whole kernel-space memory stored in RAM. This feature can be used to conveniently dump kernel memory on devices with `/dev/kmem` disabled. |
| _Other_ | Device will return `-EINVAL` | 

## Collecting debug logs

During memory flattening kflat can output a plenty of logs to ease for debugging puposes. Since, printing a lot of info to dmesg is not the best practice, Kflat implements its own message buffer that could be read from `/sys/kernel/debug/kflat`. After running kflat test or dumping memory with recipe, simply invoke `cat` on this file to collect all available debug information.

```sh
cat /sys/kernel/debug/kflat
```

## Example use of kernel API

The simplified flow of dumping kernel memory with kflat looks as follow:

```c
sizet_t mem_size = 1_MB;        // Max. size of dumped image
fd = open("/sys/kernel/debug/kflat", O_RDONLY);

mem = mmap(NULL, mem_size, PROT_READ, MAP_PRIVATE, fd, KFLAT_MMAP_FLATTEN);

struct kflat_ioctl_enable enable = {
    .pid = getpid(),
    .debug_flag = 1,    // Whether to output debug logs to dmesg
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
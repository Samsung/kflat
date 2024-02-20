# Current task_struct example

This example flattens selected fields from current `task_struct`. Once flattened,
application `task_current_client` allows user to view information about running
processes, including `pid`, `permissions`, etc.

## Build

This kernel module is build alongside all other files in this repo - simply enter root
directory of KFLAT repo and run `make` command as described in README.md. After that,
there should be file `task_current_recipe.ko` present in this directory.

The userspace app will be build automtically whenever the `task_current` target is built.

## Run

Load modules `kflat_core.ko` and `task_current_recipe.ko`. Next, use tool `tools/executor` to invoke recipe.

```bash
$ tools/executor -f -o task_struct.bin MANUAL task_struct_example
```

Finally, execute `./task_current_client <output_file>` app to test flattening and display
information about currently running processes in system.

```
$ ./task_current_client task_struct.bin
Loaded input file ./task_struct.bin
## Found 238 tasks
T[1:1], cpu: 0, prio: 120, comm: init, flags: 1077936384, utime: 128000000, stime: 2009530070
T[2:2], cpu: 0, prio: 120, comm: kthreadd, flags: 2129984, utime: 0, stime: 12000000
T[3:3], cpu: 0, prio: 100, comm: rcu_gp, flags: 69238880, utime: 0, stime: 0
T[4:4], cpu: 0, prio: 100, comm: slub_flushwq, flags: 69238880, utime: 0, stime: 0
T[5:5], cpu: 0, prio: 100, comm: netns, flags: 69238880, utime: 0, stime: 0
T[7:7], cpu: 0, prio: 100, comm: kworker/0:0H, flags: 69238880, utime: 0, stime: 0
T[9:9], cpu: 0, prio: 100, comm: mm_percpu_wq, flags: 69238880, utime: 0, stime: 0
T[11:11], cpu: 0, prio: 120, comm: rcu_tasks_kthre, flags: 2129984, utime: 0, stime: 8000000
T[12:12], cpu: 0, prio: 120, comm: rcu_tasks_trace, flags: 2129984, utime: 0, stime: 0
T[13:13], cpu: 0, prio: 120, comm: ksoftirqd/0, flags: 69238848, utime: 0, stime: 72000000
T[14:14], cpu: 1, prio: 98, comm: rcu_preempt, flags: 2129984, utime: 0, stime: 64000000
(...)
T[2381:2381], cpu: 1, prio: 120, comm: kworker/u4:3, flags: 69238880, utime: 0, stime: 12000000
T[2382:2382], cpu: 1, prio: 120, comm: kworker/u4:4, flags: 69238880, utime: 0, stime: 4000000
T[2383:2383], cpu: 1, prio: 100, comm: kworker/u5:1, flags: 69238880, utime: 0, stime: 0
T[2415:2415], cpu: 0, prio: 120, comm: executor, flags: 4194560, utime: 0, stime: 324000000
```

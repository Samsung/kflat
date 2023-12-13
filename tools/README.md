# Executor
Executor is an app that utilizes ExecFlat library to run KFLAT recipes.
It has three operating modes:
- AUTO - allows to specify a filesystem node and a file operation to be performed on the node, which is expected to trigger a recipe. 
- MANUAL - only attaches to a kernel function and waits for user to somehow trigger the recipe manually.
- LIST - lists all currently loaded kflat recipes.

## Command syntax
```
Usage: tools/executor --output PATH [--debug] [--run_recipe_now] [--skip_function_body] [--stop_machine] --poll_timeout TIMEOUT --dump_size DUMP_SIZE --verbosity VERBOSITY_LEVEL {AUTO,LIST,MANUAL}

Userspace interface for triggering KFLAT recipes.

Optional arguments:
  -o, --output PATH                File to save the kflat dump. [default: "dump.kflat"]
  -d, --debug                      Enable KFLAT debug logging to dmesg. 
  -f, --run_recipe_now             Execute KFLAT recipe directly from the IOCTL without attachking to any kernel function. 
  -n, --skip_function_body         Do not execute target function body after flattening memory. 
  -s, --stop_machine               Execute KFLAT recipe under kernel's stop_machine mode. 
  -p, --poll_timeout TIMEOUT       In miliseconds. Timeout for recipe execution [default: 5000]
  -u, --dump_size DUMP_SIZE        Max dump size of the kflat image - effectively the size of mmaped kflat memory. [default: 104857600]
  -y, --verbosity VERBOSITY_LEVEL  Verbosity level of ExecFlat library. [default: "INFO"]

Subcommands:
  AUTO                            Enable flattening and automatically trigger a recipe via one of available interfaces.
  LIST                            List all recipe modules.
  MANUAL                          Enable flattening but you need to trigger a recipe by yourself.
``` 
The optional arguments listed above are shared between all subcommands, so they must be placed BEFORE a subcommand argument.
```
# WRONG
./executor MANUAL --verbosity DEBUG
# CORRECT
./executor --verbosity DEBUG MANUAL
```
Specifying a subcommand may introduce more arguments. 
### `AUTO` subcommand
```
Usage: AUTO [--help] [--version] [--io_timeout TIMEOUT] recipe interface target

Enable flattening and automatically trigger a recipe via one of available interfaces.

Positional arguments:
  recipe                    Recipe to be run 
  interface                 Select interface type (READ, SHOW, WRITE, STORE, IOCTL, COMPAT_IOCTL). 
  target                    File that the INTERFACE will be called on. 

Optional arguments:
  -h, --help                shows help message and exits 
  -v, --version             prints version information and exits 
  -t, --io_timeout TIMEOUT  In seconds. Timeout for waiting on the I/O interface operation. [default: 2]
```
`AUTO` subcommand introduces 3 positional arguments `recipe interface target` and one optional `--io_timeout`. All those arguments are specific to the `AUTO` subcommand, so they need to be placed AFTER the `AUTO` keyword.

Example:
```bash
# Enable KFLAT debug info
# Set output dump file to "myimage.kflat"
# Set AUTO mode IO operation timeout to 10s (how long to wait for the READ call to complete)
# Use AUTO mode on "random_read_iter" recipe
# Trigger the recipe by calling READ on "/dev/random"
./executor -d -o myimage.kflat AUTO -t 10 random_read_iter READ /dev/random 
```
### `MANUAL` subcommand
```
Usage: MANUAL [--help] [--version] recipe

Enable flattening but you need to trigger a recipe by yourself.

Positional arguments:
  recipe         Recipe to be run 

Optional arguments:
  -h, --help     shows help message and exits 
  -v, --version  prints version information and exits
```

`MANUAL` subcommand only needs one positional argument - namely `recipe`.

Example:
```bash
# Enable KFLAT debug info
# Set output dump file to "myimage.kflat"
# Set recipe poll timeout (how long should executor wait for the dump to become ready) to 10000 miliseconds.
# Use MANUAL mode
./executor -d -o myimage.kflat -p 10000 MANUAL do_init_module
# Now, the executor will be waiting for the recipe to activate
# The user should perform some action to trigger the recipe
# In this case - the action should be inserting a kernel module
insmod some_module.ko
```

### `LIST` subcommand
```
Usage: LIST [--help] [--version]

List all recipe modules.

Optional arguments:
  -h, --help     shows help message and exits 
  -v, --version  prints version information and exits
```
`LIST` subcommand doesn't require any arguments. It just lists all currently loaded KFLAT recipes
```bash
./executor LIST
```

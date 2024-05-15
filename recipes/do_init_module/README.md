## Building
All necessary binaries (kflat core + this module + client app) can be build by compiling the `do_init_module` CMake target.
```bash
# In kflat/build
cmake --build . --target do_init_module
```

## Module loading

When LKM is loaded, the function `do_init_module` is called. We hook on this function and extract information about the module that's being loaded. 

## Usage

```bash
# First load the kflat core
insmod core/kflat_core.ko

# Then load the recipe
cd recipes/do_init_module
insmod do_init_module.ko

# Run it
./do_init_module_client
``` 

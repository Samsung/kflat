# Module loading

When LKM is loaded, the function `do_init_module` is called. We hook on this function and extract information about the module that's being loaded.

## Usage

```bash
# First load the kflat core
insmod core/kflat_core.ko

# Then load the recipe
cd recipes/do_init_module
insmod do_init_module.ko

# Compile the client_app using
g++ -I../../lib -I../../include/ -o client_app client_app.cpp ../../lib/libExecFlat.a

# Run it
./client_app
``` 

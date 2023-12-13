# ExecFlat - library that makes running KFLAT recipes easy!
Using the KFLAT kernel module requires performing some low level operations such as mmaping memory or running IOCTLs.
The goal of this library is to make it as easy as possible to run a KFLAT recipe, without having to know anothing about the internals of KFLAT.

## API
ExecFlat provides a library for C++ applications.

### C++ Interface
There are two enums inside a `ExecFlatOpts` namespace used for ExecFlat configuration.
```cpp
/**
 * 
 */
namespace ExecFlatOpts{
    /**
     * @brief Used as a ExecFlat contructor parameter \n
     * that determines the verbosity level of the ExecFlat library.
     * 
     */
    enum ExecFlatVerbosity {
        SUPRESS,
        ERROR,
        WARNING,
        INFO,
        DEBUG,
    };

    /**
     * @brief Supported types of file operations for automatic recipe triggering.
     * 
     */
    enum ExecFlatInterface {
        READ,
        SHOW,
        WRITE,
        STORE,
        IOCTL,
    };
}
```
This is the main ExecFlat class that is used for running recipes.
```cpp
/**
 * @brief Construct and initialize a new ExecFlat object.
 * 
 * @param dump_size Max size of kflat memory dump.
 * @param log_level One of ExecFlatVerbosity enum members.
 */
ExecFlat(size_t dump_size, ExecFlatVerbosity log_level);

/**
 * @brief Run a KFLAT recipe with a given target file. After enabling KFLAT, chosen file operation will be called on the target.   
 * 
 * @param interface One of ExecFlatInterface. The type of file operation to perform on TARGET.
 * @param target Path to the file to call INTERFACE on.
 * @param recipe Name of the KFLAT recipe. 
 * @param outfile Path to the file where the dump will be saved.
 * @param use_stop_machine Execute the KFLAT recipe under kernel's stop_machine mode.
 * @param debug Enable KFLAT LKM logging to dmesg.
 * @param skip_func_body Skip executing function body after the recipe finishes flattening.
 * @param run_recipe_now Execute KFLAT recipe directly from IOCTL without attaching to any kernel function.
 * @param target_timeout In seconds. Timeout for INTERFACE call on TARGET.
 * @param poll_timeout In miliseconds. Timeout for recipe execution.
 */
void run_recipe(
    ExecFlatInterface interface, 
    const fs::path &target, 
    const std::string &recipe, 
    const fs::path &outfile, 
    bool use_stop_machine=false, 
    bool debug=true, 
    bool skip_func_body=false,
    bool run_recipe_now=false,
    unsigned int target_timeout=0,
    int poll_timeout=-1
);

/** 
 * @brief Run a KFLAT recipe without any specified target. The recipe will wait for an external trigger (e.g. user can manually trigger the target function).
 * 
 * @param recipe Name of the KFLAT recipe. 
 * @param outfile Path to the file where the dump will be saved.
 * @param use_stop_machine Execute the KFLAT recipe under kernel's stop_machine mode.
 * @param debug Enable KFLAT LKM logging to dmesg.
 * @param skip_func_body Skip executing function body after the recipe finishes flattening.
 * @param run_recipe_now Execute KFLAT recipe directly from IOCTL without attaching to any kernel function.
 * @param poll_timeout In miliseconds. Timeout for recipe execution.
 */
void run_recipe_no_target(
    const std::string &recipe, 
    const fs::path &outfile, 
    bool use_stop_machine=false, 
    bool debug=true, 
    bool skip_func_body=false,
    bool run_recipe_now=false,
    int poll_timeout=-1
);

/**
 * @brief Run a KFLAT recipe with a custom trigger function.
 * 
 * @param custom_trigger Function with signature int (). Function that will be executed after enabling KFLAT. Executing this should trigger the kernel function with recipe attached.   
* @param recipe Name of the KFLAT recipe. 
* @param outfile Path to the file where the dump will be saved.
* @param use_stop_machine Execute the KFLAT recipe under kernel's stop_machine mode.
* @param debug Enable KFLAT LKM logging to dmesg.
* @param skip_func_body Skip executing function body after the recipe finishes flattening.
* @param run_recipe_now Execute KFLAT recipe directly from IOCTL without attaching to any kernel function.
* @param target_timeout In seconds. Timeout for INTERFACE call on TARGET.
* @param poll_timeout In miliseconds. Timeout for recipe execution. 
*/
void run_recipe_custom_target(
    std::function<int ()> custom_trigger, 
    const std::string &recipe, 
    const fs::path &outfile, 
    bool use_stop_machine=false, 
    bool debug=true, 
    bool skip_func_body=false,
    bool run_recipe_now=false,
    unsigned int target_timeout=0,
    int poll_timeout=-1
);


/**
 * @brief Read all KFLAT recipes available to execute.
 * 
 * @return std::vector<std::string> Vector of strings with names of loaded recipes
 */
std::vector<std::string> get_loaded_recipes();
```



## Examples
### No target
Let's create a simple app that runs the `dummy_recipe` recipe and saves the flattening result into `outfile.kflat`. 
```cpp
/* example_execflat.cpp */
#include "ExecFlat.hpp"

int main() {
    try {
        ExecFlat flat(1024, ExecFlatOpts::DEBUG);
        flat.run_recipe_no_target("dummy_recipe", "outfile.kflat");
    } catch (const std::runtime_error &err) {
        std::cerr << err.what();
        return 1;
    }

    return 0;
}
```
Now let's build it with
```bash
KFLAT_DIR=/path/to/kflat
g++ -I$KFLAT_DIR/lib -I$KFLAT_DIR/include example_execflat.cpp $KFLAT_DIR/lib/libExecFlat.so -o example_execflat
```
and run
```bash
./example_execflat
```
Since we used `run_recipe_no_target`, we must perform an action that will trigger the `dummy_recipe`. 

### Predefined target
The only thing that changes is that `run_recipe` is called this time. We want to execute `dummy_recipe`. In this example by using `run_recipe`, we can make ExecLib automatically call `read` on the file `/dev/mydevice`, which is supposed to trigger the recipe. This is useful, if we want to flatten data from file operation handler of devices (`read, write, ioctl, ...`).  
```cpp
/* example_execflat.cpp */
#include "ExecFlat.hpp"

int main() {
    try {
        ExecFlat flat(1024, ExecFlatOpts::DEBUG);
        flat.run_recipe(ExecFlatOpts::READ, "/dev/mydevice", "dummy_recipe", "outfile.kflat");
    } catch (const std::runtime_error &err) {
        std::cerr << err.what();
        return 1;
    }

    return 0;
}
```
Since the target will be run automatically, we onyl have to compile the app and run it.

```bash
KFLAT_DIR=/path/to/kflat
g++ -I$KFLAT_DIR/lib -I$KFLAT_DIR/include example_execflat.cpp $KFLAT_DIR/lib/libExecFlat.so -o example_execflat
./example_execflat
```

## Custom target
This time we are calling the `run_recipe_custom_target` method. This allows us to specify our own function for ExecLib to execute, that triggers the recipe.

```cpp
/* example_execflat.cpp */
#include "ExecFlat.hpp"

int trigger_function() {
    /* Some code that will trigger the dummy_recipe */
}

int main() {
    try {
        ExecFlat flat(1024, ExecFlatOpts::DEBUG);
        flat.run_recipe_custom_target(trigger_function, "dummy_recipe", "outfile.kflat");
    } catch (const std::runtime_error &err) {
        std::cerr << err.what();
        return 1;
    }

    return 0;
}
```
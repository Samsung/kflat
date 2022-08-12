# nproctdb - Kflat recipes generator

`nproctdb` is a Python tool used for automatic generation of KFLAT recipes. With this script, you can quickly generate necessary recipes to dump memory of sturctures used in off-targets generated with [Auto-Of-Target suite](https://github.com/Samsung/auto_off_target). Script utilizes DB.json database that can be generated with build tracing infrastructure available in [CAS repository](https://github.com/Samsung/CAS).


## Setup
Make sure you've got recent Python3 version installed on your computer. Additionally, you'll need a copy of `libftdb.so` library built from CAS respository, as well as DB.JSON database for your project.


## Usage
Most basic usage of nproctdb is to create recipe for selected kernel structure `device`, traced from the entry point `sshot_ctrl_store`:

```sh
./nproctdb.py -d vmlinux_db.json.img -c linux_recipes.cfg device sshot_ctrl_store
```

Parameter `-d` specifies the path to db.json database file (default: `db.json`). Scripts accepts DB.json in both available formats: the plain JSON and flattened image (for details refer to CAS repository). Additionaly, optional parameter `-c` specified the structure config file to be used during recipes generation. With config file, user can limit the fields being dumped from the structures, for instance specify that only field `private_data` should be dumped from structure `file`.

Upon execution, `nproctdb` will collect all functions accessible from the given entry point `sshot_ctrl_store`. Next, all these functions are traced for usage of `void*` pointers and `container_of` macros. Finally, script recursively dumps structure definitions, starting from the given structure `device`. Thanks to the traced information regarding `void*` pointers casting, it is able to properly deduce the underlying types of these generic pointers and pull their definitions as well.


> *Warning*
>
> Upon first launch, nproctdb generates preprocessed database from db.json. This process may require a LOT of RAM in you machine. Use it carrefully!


## Structures configs


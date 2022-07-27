# nproctdb - Kflat recipes generator

`nproctdb` is a Python tool used for automatic generation of kflat recipes. With this script, user can quickly generate necessary recipes to dump memory used in off-target generated with [Auto-Of-Target suite](https://github.com/Samsung/auto_off_target).


## Setup
Make sure you've got recent Python3 version installed on your computer. Additionally, you'll need a copy of `libftdb.so` library built from [CAS repository](https://github.com/Samsung/CAS), as well as DB.JSON database for your project.

## Usage
Most basic usage of nproctdb is to create recipe for selected kernel structure and its dependencies.

```sh
./nproctdb.py -d vmlinux_db.json.img -c linux_recipes.cfg device sshot_ctrl_store
```


> *Warning*
> Upon first launch, nproctdb generates preprocessed database from db.json. This process requires a LOT of RAM in you machine - at least 50GB for full vmlinux. Use it carrefully!

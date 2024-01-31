# Userspace memory flattening
A recipe created to test the user memory flattening.
## Building
In the `kflat/` directory run  
```bash
make -j32
```
and in the `kflat/recipes/userspace_flattening/` run
```bash
g++ -I../../lib/ -I../../include/ -o ioctl_client ioctl_client.cpp ../../lib/libExecFlat.a
```

## Running
Load kernel modules (from the `kflat/` directory):
```bash
insmod core/kflat_core.ko
insmod recipes/userspace_flattening/userspace_flattening.ko
insmod recipes/userspace_flattening/ioctl_module/ioctl_module.ko
```
and run the userspace client:
```bash
recipes/userspace_flattening/ioctl_client
```
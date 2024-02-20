# Userspace memory flattening
A recipe created to test the user memory flattening.
## Building
The `ioctl_module` and the `client_app` should be build automatically whenever the `userspace_flattening` target is built. 

## Running
Load kernel modules (from the CMake build directory):
```bash
insmod core/kflat_core.ko
insmod recipes/userspace_flattening/userspace_flattening.ko
insmod recipes/userspace_flattening/ioctl_module/ioctl_module.ko
```
and run the userspace client:
```bash
recipes/userspace_flattening/ioctl_client
```
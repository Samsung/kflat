# KFLAT/UFLAT project libraries

This directory hosts the source code of userspace utility libraries related to Kflat and Uflat projects, in particular:

- **uflat**: userspace port of Kflat kernel module, capable of serializing memory from any C user application,
- **unflatten**: library capable of loading and examining flattened memory image.

For detailed instructions for each of these libraries, please refer to the following doc files:
- Uflat - [UFLAT.md](UFLAT.md)
- Unflatten - [Unflatten.md](Unflatten.md)

## Building

Both of these libraries are built during full Kflat repository build (i.e. when running `make` without targets in the root project
directory). Apart from that, you can build only selected library with commands:

```sh
# Build Uflat
make uflat

# Build Unflattten library
make library
```

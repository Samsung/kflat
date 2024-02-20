# KFLAT/UFLAT project libraries

This directory hosts the source code of userspace utility libraries related to Kflat and Uflat projects, in particular:

- **uflat**: userspace port of Kflat kernel module, capable of serializing memory from any C user application,
- **unflatten**: library capable of loading and examining flattened memory image.
- **ExecFlat**: library that provides a simple API for running KFLAT recipes from custom C++ applications.

For detailed instructions for each of these libraries, please refer to the following doc files:
- Uflat - [UFLAT.md](UFLAT.md)
- Unflatten - [Unflatten.md](Unflatten.md)
- ExecFlat - [ExecFlat.md](ExecFlat.md)

## Building

Both of these libraries are built during full Kflat repository build. Apart from that, you can build only selected library with commands:

```sh
mkdir -p build && cd build
cmake ..
# Build Uflat
cmake --build . --target uflat
# Build Unflattten library
cmake --build . --target unflatten
```

If you want to build the klee libraries, you might have to specify the path where the `clang++-13` is located, as well as the path to the klee libc++ with commands 
```bash
cmake -DKLEE_CLANGXX_PATH=<path> -DKLEE_LIBCXX_INSTALL=<path> ..
cmake --build . --target klee_libs
```

If you want to build the libraries with DFSAN, you need to specify the path where the `clang-15` is located:

```bash
cmake -DDFSAN_CLANG_PATH==<path> ..
cmake --build . --target dfsan_libs
```
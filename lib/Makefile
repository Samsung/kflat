CFLAGS = -Iinclude_priv/ -I../include/ -O3 -Wall -fPIC
LDFLAGS = --shared -fPIC
UNFLAT_TARGET = 
FLAT_TARGET = 

#
# Generic targets
#
rbtree.o: rbtree.c
	$(CXX) $(CFLAGS) -c -o $@ $^

flatten_impl.o: ../core/flatten_impl.c ../core/flatten_impl.h
	$(CXX) $(CFLAGS) -DFLATTEN_USERSPACE_BSP -I../core/ -c -o $@ $<

uflat.o: uflat.c uflat.h
	$(CXX) $(CFLAGS) -DFLATTEN_USERSPACE_BSP -c -o $@ $<

funcsymsutils.o: funcsymsutils.c funcsymsutils.h
	$(CXX) $(CFLAGS) -DFLATTEN_USERSPACE_BSP -c -o $@ $<

unflatten.o: unflatten.cpp unflatten.hpp
	$(CXX) $(CFLAGS) -ggdb3 -c -o $@ $<

libunflatten_$(ARCH).so: unflatten.o rbtree.o
	$(CXX) $(LDFLAGS) -o $@ $^

libunflatten_$(ARCH).a: unflatten.o rbtree.o
	gcc-ar rcs $@ $^

libuflat_$(ARCH).so: uflat.o flatten_impl.o rbtree.o unflatten.o funcsymsutils.o
	$(CXX) $(LDFLAGS) -ldl -o $@ $^

libuflat_$(ARCH).a: uflat.o flatten_impl.o rbtree.o unflatten.o funcsymsutils.o
	gcc-ar rcs $@ $^

#
# KLEE libraries
#
unflatten.bc: unflatten.cpp unflatten.hpp
	clang++-11 -emit-llvm -o $@ -D KLEE_SUPPORT -c -Iinclude_priv/ -I../include/ -std=c++11 -I${KLEE_LIBCXX_INSTALL}/include/c++/v1/ -nostdinc++ unflatten.cpp

rbtree.bc: rbtree.c
	clang++-11 -emit-llvm -o $@ -D KLEE_SUPPORT -c -Iinclude_priv/ -I../include/ -std=c++11 -I${KLEE_LIBCXX_INSTALL}/include/c++/v1/ -nostdinc++ rbtree.c

#
# DFSAN targets
#
unflatten_dfsan.o: unflatten.cpp unflatten.hpp
	clang-15 $(CFLAGS) -fsanitize=dataflow -mllvm -dfsan-event-callbacks -c -o $@ $<

rbtree_dfsan.o: rbtree.c
	clang-15 $(CFLAGS) -fsanitize=dataflow -mllvm -dfsan-event-callbacks -c -o $@ $^

libunflatten_$(ARCH)_dfsan.a: unflatten_dfsan.o rbtree_dfsan.o
	ar rcs $@ $^


FLAT_TARGET += libuflat_$(ARCH).a libuflat_$(ARCH).so

#
# When building for ARM64, extra provide x86 version of
#  library files for easier testing on host machine
#
ifeq ($(ARCH), arm64)
rbtree_x86_64.o: rbtree.c
	clang++ $(CFLAGS) -c -o $@ $^

unflatten_x86_64.o: unflatten.cpp unflatten.hpp
	clang++ $(CFLAGS) -c -o $@ $<

libunflatten_x86_64.so: unflatten_x86_64.o rbtree_x86_64.o
	clang++ $(LDFLAGS) -o $@ $^

libunflatten_x86_64.a: unflatten_x86_64.o rbtree_x86_64.o
	ar rcs $@ $^

UNFLAT_TARGET += libunflatten_$(ARCH).a libunflatten_$(ARCH).so libunflatten_x86_64.a libunflatten_x86_64.so

else

UNFLAT_TARGET += libunflatten_$(ARCH).a libunflatten_$(ARCH).so

endif

# Check if clang-9 is available. If so, built libraries for KLEE as well
ifneq (${KLEE_LIBCXX_INSTALL},)
UNFLAT_TARGET += unflatten.bc rbtree.bc
endif

# Check if clang-15 is avaible. If so, built DFSAN libraries for AoT
ifneq ($(shell which clang-15),)
UNFLAT_TARGET += libunflatten_$(ARCH)_dfsan.a
endif

all: $(UNFLAT_TARGET) $(FLAT_TARGET)

.PHONY: uflat
uflat: $(FLAT_TARGET)

.PHONY: unflatten
unflatten: $(UNFLAT_TARGET)

.PHONY: clean
clean:
	rm -f *.o *.so *.a *.bc

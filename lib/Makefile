CFLAGS = -Iinclude_priv/ -Wall -O3 -fPIC
LDFLAGS = --shared -fPIC
ALL_TARGET = 

#
# Generic targets
#
rbtree.o: rbtree.c
	$(CXX) $(CFLAGS) -c -o $@ $^

unflatten.o: unflatten.cpp unflatten.hpp
	$(CXX) $(CFLAGS) -c -o $@ $<

libunflatten_$(ARCH).so: unflatten.o rbtree.o
	$(CXX) $(LDFLAGS) -o $@ $^

libunflatten_$(ARCH).a: unflatten.o rbtree.o
	ar rcs $@ $^

#
# KLEE libraries
#
unflatten.bc: unflatten.cpp unflatten.hpp
	clang++-9 -emit-llvm -o $@ -c -Iinclude_priv/ -std=c++11 -I${KLEE_LIBCXX_INSTALL}/include/c++/v1/ -nostdinc++ unflatten.cpp

rbtree.bc: rbtree.c
	clang++-9 -emit-llvm -o $@ -c -Iinclude_priv/ -std=c++11 -I${KLEE_LIBCXX_INSTALL}/include/c++/v1/ -nostdinc++ rbtree.c

#
# DFSAN targets
#
unflatten_dfsan.o: unflatten.cpp unflatten.hpp
	clang-15 $(CFLAGS) -fsanitize=dataflow -mllvm -dfsan-event-callbacks -c -o $@ $<

rbtree_dfsan.o: rbtree.c
	clang-15 $(CFLAGS) -fsanitize=dataflow -mllvm -dfsan-event-callbacks -c -o $@ $^

libunflatten_$(ARCH)_dfsan.a: unflatten_dfsan.o rbtree_dfsan.o
	ar rcs $@ $^

#
# When building for ARM64, extra provide x86 version of
#  library files for easier testing on host machine
#
ifeq ($(ARCH), arm64)
rbtree_x86_64.o: rbtree.c
	g++ $(CFLAGS) -c -o $@ $^

unflatten_x86_64.o: unflatten.cpp unflatten.hpp
	g++ $(CFLAGS) -c -o $@ $<

libunflatten_x86_64.so: unflatten_x86_64.o rbtree_x86_64.o
	g++ $(LDFLAGS) -o $@ $^

libunflatten_x86_64.a: unflatten_x86_64.o rbtree_x86_64.o
	ar rcs $@ $^

ALL_TARGET += libunflatten_arm64.a libunflatten_arm64.so libunflatten_x86_64.a libunflatten_x86_64.so

else

ALL_TARGET += libunflatten_x86_64.a libunflatten_x86_64.so

endif

# Check if clang-9 is available. If so, built libraries for KLEE as well
ifneq (${KLEE_LIBCXX_INSTALL},)
ALL_TARGET += unflatten.bc rbtree.bc
endif

# Check if clang-15 is avaible. If so, built DFSAN libraries for AoT
ifneq ($(shell which clang-15),)
ALL_TARGET += libunflatten_$(ARCH)_dfsan.a
endif

all: $(ALL_TARGET)

.PHONY: clean
clean:
	rm -f *.o *.so *.a *.bc

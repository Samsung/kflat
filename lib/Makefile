CFLAGS = -Iinclude_priv/ -Wall -O3 -fPIC
LDFLAGS = --shared -fPIC

#
# Generic targets
#
rbtree.o: rbtree.c
	$(CXX) $(CFLAGS) -c -o $@ $^

unflatten.o: unflatten.cpp unflatten.hpp
	$(CXX) $(CFLAGS) -c -o $@ $<

libunflatten.so: unflatten.o rbtree.o
	$(CXX) $(LDFLAGS) -o $@ $^

libunflatten.a: unflatten.o rbtree.o
	ar rcs $@ $^

#
# When building for ARM64, extra provide x86 version of
#  library files for easier testing on host machine
#
ifeq ($(ARCH), arm64)
rbtree_x86.o: rbtree.c
	g++ $(CFLAGS) -c -o $@ $^

unflatten_x86.o: unflatten.cpp unflatten.hpp
	g++ $(CFLAGS) -c -o $@ $<

libunflatten_x86.so: unflatten_x86.o rbtree_x86.o
	g++ $(LDFLAGS) -o $@ $^

libunflatten_x86.a: unflatten_x86.o rbtree_x86.o
	ar rcs $@ $^

all: libunflatten.a libunflatten.so libunflatten_x86.a libunflatten_x86.so

else
all: libunflatten.a libunflatten.so

endif

.PHONY: clean
clean:
	rm -f *.o *.so *.a

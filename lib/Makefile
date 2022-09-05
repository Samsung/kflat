CFLAGS = -Iinclude_priv/ -Wall -O3 -fPIC -ggdb3
LDFLAGS = --shared -fPIC

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

all: libunflatten_arm64.a libunflatten_arm64.so libunflatten_x86_64.a libunflatten_x86_64.so

else
all: libunflatten_x86_64.a libunflatten_x86_64.so

endif

.PHONY: clean
clean:
	rm -f *.o *.so *.a

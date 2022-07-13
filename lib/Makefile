rbtree.o: rbtree.c
	$(CXX) -Iinclude/ -Wall -O3 -fPIC -c -o $@ $^

unflatten.o: unflatten.cpp unflatten.hpp
	$(CXX) -Iinclude/ -Wall -O3 -fPIC -c -o $@ $<

libunflatten.so: unflatten.o rbtree.o
	$(CXX) -Wall -O3 --shared -fPIC -o $@ $^

libunflatten.a: unflatten.o rbtree.o
	ar rcs $@ $^

ifeq ($(ARCH), arm64)
rbtree_x86.o: rbtree.c
	g++ -Iinclude/ -Wall -O3 -fPIC -c -o $@ $^

unflatten_x86.o: unflatten.cpp unflatten.hpp
	g++ -Iinclude/ -Wall -O3 -fPIC -c -o $@ $<

libunflatten_x86.so: unflatten_x86.o rbtree_x86.o
	g++ -Wall -O3 --shared -fPIC -o $@ $^

libunflatten_x86.a: unflatten_x86.o rbtree_x86.o
	ar rcs $@ $^

all: libunflatten.a libunflatten.so libunflatten_x86.a libunflatten_x86.so

else
all: libunflatten.a libunflatten.so

endif

clean:
	rm -f *.o *.so *.a

export INCLUDE_PATH=$(PWD)/include/

common.o: common.c
	$(CC) $(CFLAGS) -isystem /usr/aarch64-linux-gnu/include -c -o $@ $^

common_32.o: common.c
	arm-linux-gnueabihf-gcc -c -o $@ $^

executor: executor.c common.o
	$(CC) $(CFLAGS) -DENV_64 -I${INCLUDE_PATH} -isystem /usr/aarch64-linux-gnu/include --static -o $@ $^

executor_32: executor.c common_32.o
	arm-linux-gnueabihf-gcc -DENV_32 -I${INCLUDE_PATH} --static -o $@ $^

kflattest: kflattest.c common.o
	$(CC) $(CFLAGS) -I${INCLUDE_PATH} -isystem /usr/aarch64-linux-gnu/include --static -o $@ $^

imginfo: imginfo.cpp
	$(CXX) -Wall -I${INCLUDE_PATH} -I$(PWD)/lib/include_priv -isystem /usr/aarch64-linux-gnu/include -ggdb3 --static -o $@ imginfo.cpp ../lib/libunflatten.a

ifeq ($(ARCH), arm64)
imginfo_x86: imginfo.cpp
	g++ -Wall -I$(PWD)/lib/include_priv -ggdb3 -o $@ $< ../lib/libunflatten_x86.a

all: executor executor_32 kflattest imginfo imginfo_x86

else
all: executor executor_32 kflattest imginfo

endif

clean:
	rm -f *.o executor executor_32 kflattest imginfo imginfo_x86

export INCLUDE_PATH=$(PWD)/include/

CFLAGS += -I${INCLUDE_PATH} -isystem /usr/aarch64-linux-gnu/include
EXTRA_CFLAGS = -ggdb3 -I$(PWD)/lib

#
# Test files from tests/ directory
#
TEST_SRCS = $(wildcard $(PWD)/tests/*.c)
TEST_FILENAMES = $(notdir $(TEST_SRCS))
TEST_OBJS = $(addprefix $(PWD)/tests/user_, $(TEST_FILENAMES:.c=.o))

#
# Build targets
#
$(TEST_OBJS): $(TEST_SRCS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $<

common.o: common.c
	$(CC) $(CFLAGS) --static -c -o $@ $^

executor: executor.c common.o
	$(CC) $(CFLAGS) -DENV_64 --static -o $@ $^

kflattest: kflattest.c common.o $(TEST_SRCS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) --static -o $@ $^ $(PWD)/lib/libunflatten_$(ARCH).a -lstdc++ -lm

imginfo: imginfo.cpp
	$(CXX) -Wall -I${INCLUDE_PATH} -I$(PWD)/lib/include_priv -isystem /usr/aarch64-linux-gnu/include -ggdb3 --static -o $@ imginfo.cpp ../lib/libunflatten_$(ARCH).a


ifeq ($(ARCH), arm64)
imginfo_x86: imginfo.cpp
	g++ -Wall -I$(PWD)/lib/include_priv -ggdb3 -o $@ $< ../lib/libunflatten_x86_64.a

common_32.o: common.c
	arm-linux-gnueabihf-gcc -c -o $@ $^

executor_32: executor.c common_32.o
	arm-linux-gnueabihf-gcc -DENV_32 -I${INCLUDE_PATH} --static -o $@ $^

all: executor executor_32 kflattest imginfo imginfo_x86
else
all: executor kflattest imginfo
endif


clean:
	rm -f *.o executor executor_32 kflattest imginfo imginfo_x86 $(PWD)/tests/*.o $(PWD)/tests/tests_list.h

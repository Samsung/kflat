export INCLUDE_PATH=$(PWD)/include/

CFLAGS += -I${INCLUDE_PATH} -I$(PWD)/tests -DFLATTEN_USERSPACE_BSP
EXTRA_CFLAGS = -ggdb3 -I$(PWD)/lib -Og

ifeq ($(ARCH), arm64)
CFLAGS += -isystem /usr/aarch64-linux-gnu/include
endif

#
# Generate lists of available tests for uflat and kflat test apps
#
../tests/uflat_tests_list.h: Makefile
	@echo "** Generating list of UFLAT tests **"
	$(shell M=$(PWD) ../tests/tests_list_gen.sh)

#
# Test files from tests/ directory
#
TEST_SRCS = $(wildcard $(PWD)/tests/*.c)
TEST_FILENAMES = $(notdir $(TEST_SRCS))
TEST_OBJS = $(addprefix $(PWD)/tests/user_, $(TEST_FILENAMES:.c=.o))

KFLAT_TEST_SRCS = $(wildcard $(PWD)/tests/kflat/*.c)
KFLAT_TEST_FILENAMES = $(notdir $(KFLAT_TEST_SRCS))
KFLAT_TEST_OBJS = $(addprefix $(PWD)/tests/kflat/user_, $(KFLAT_TEST_FILENAMES:.c=.o))

UFLAT_TEST_SRCS = $(wildcard $(PWD)/tests/uflat/*.c)
UFLAT_TEST_FILENAMES = $(notdir $(UFLAT_TEST_SRCS))
UFLAT_TEST_OBJS = $(addprefix $(PWD)/tests/uflat/user_, $(UFLAT_TEST_FILENAMES:.c=.o))

UFLAT_SPEC_TEST_OBJS = $(subst uflat/user_,uflat/test_,$(UFLAT_TEST_OBJS))
UFLAT_COMMON_TEST_OBJS = $(subst tests/user_,tests/test_,$(TEST_OBJS))

#
# Build targets for tests binaries
#

# Common validator
$(TEST_OBJS): $(PWD)/tests/user_%.o: $(PWD)/tests/%.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $< -D__VALIDATOR__

# KFLAT-specific validator
$(KFLAT_TEST_OBJS): $(PWD)/tests/kflat/user_%.o: $(PWD)/tests/kflat/%.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $< -D__VALIDATOR__

# UFLAT-common tests
$(UFLAT_SPEC_TEST_OBJS): $(PWD)/tests/uflat/test_%.o: $(PWD)/tests/uflat/%.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $< -D__TESTER__ -D__VALIDATOR__ -I$(PWD)/lib/include_priv

# UFLAT-specific tests
$(UFLAT_COMMON_TEST_OBJS): $(PWD)/tests/test_%.o: $(PWD)/tests/%.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $< -D__TESTER__ -D__VALIDATOR__ -I$(PWD)/lib/include_priv

#
# Build targets
#
common.o: common.c
	$(CC) $(CFLAGS) --static -c -o $@ $^

executor: executor.c common.o
	$(CC) $(CFLAGS) -DENV_64 --static -o $@ $^

kflattest: kflattest.c common.o $(TEST_OBJS) $(KFLAT_TEST_OBJS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) --static -o $@ $^ $(PWD)/lib/libunflatten_$(ARCH).a -lstdc++ -lm -D__VALIDATOR__

uflattest: uflattest.c common.o $(UFLAT_COMMON_TEST_OBJS) $(UFLAT_SPEC_TEST_OBJS) ../tests/uflat_tests_list.h
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $(filter-out %.h,$^) $(PWD)/lib/libuflat_$(ARCH).a -lstdc++ -lm -ldl -I$(PWD)/lib/include_priv -D__VALIDATOR__ -D__TESTER__

# ARM specific targets
common_32.o: common.c
	arm-linux-gnueabihf-gcc -c -o $@ $^

executor_32: executor.c common_32.o
	arm-linux-gnueabihf-gcc -DENV_32 -I${INCLUDE_PATH} --static -o $@ $^


ifeq ($(ARCH), arm64)
all: executor executor_32 kflattest uflattest
else
all: executor kflattest uflattest
endif


clean:
	rm -f *.o executor executor_32 kflattest uflattest \
			$(PWD)/tests/*.o $(PWD)/tests/.*.o.cmd \
			$(PWD)/tests/tests_list.h $(PWD)/tests/uflat_tests_list.h $(PWD)/tests/kflat_tests_list.h \
			$(PWD)/tests/kflat/*.o $(PWD)/tests/kflat/.*.o.cmd \
			$(PWD)/tests/uflat/*.o $(PWD)/tests/uflat/.*.o.cmd

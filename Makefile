# Samsung R&D Poland - Mobile Security Group

PWD := $(shell pwd)
KDIR ?= $(KERNEL_DIR)
CCDIR ?= $(CLANG_DIR)
OPTS ?= $(KFLAT_OPTS)

WARN_DEFAULT_ARCH := false
WARN_DEFAULT_KDIR := false

ifneq ($(RECIPE_DIRS),)
  export RECIPE_DIRS
endif

.DEFAULT_GOAL := default

ifeq ($(KDIR),)
  KDIR := /lib/modules/$(shell uname -r)/build
	WARN_DEFAULT_KDIR := true
endif

ifeq ($(CCDIR),)
  $(info Using default system compiler - CC=$(CC), LD=$(LD))
else
  export CC := $(CCDIR)/bin/clang.real
  export LD := $(CCDIR)/bin/ld.lld
endif

ifeq ($(ARCH),)
  export ARCH := $(shell arch)
  WARN_DEFAULT_ARCH := true
endif

ifeq ($(ARCH),arm64)
  export CROSS_COMPILE := aarch64-linux-gnu-
  export CXX := aarch64-linux-gnu-g++
  export CFLAGS := "--target=aarch64-linux-gnu --prefix=aarch64-linux-gnu-"
else ifeq ($(ARCH),x86_64)
  export CXX := g++
else
  $(error Unsupported architecture "$(ARCH)")
endif


default:
ifeq ($(WARN_DEFAULT_ARCH), true)
	$(info Architecture not specified, defaulting to $(ARCH))
endif
ifeq ($(WARN_DEFAULT_KDIR), true)
	$(info KDIR is not specified, defaulting to current kernel headers - $(KDIR))
endif
	$(MAKE) -C $(KDIR) M=$(PWD)/core CC=$(CC) LD=$(LD) CFLAGS=$(CFLAGS) OPTS=$(KFLAT_OPTS) modules
	$(MAKE) -C $(KDIR) M=$(PWD)/recipes CC=$(CC) LD=$(LD) CFLAGS=$(CFLAGS) modules
	$(MAKE) -C $(PWD)/lib KLEE_LIBCXX_INSTALL=$(KLEE_LIBCXX_INSTALL) all
	$(MAKE) -C $(PWD)/tools all

.PHONY: library
library:
	$(MAKE) -C $(PWD)/lib unflatten

.PHONY: uflat
uflat:
	$(MAKE) -C $(PWD)/lib uflat
	$(MAKE) -C $(PWD)/tools uflattest

.PHONY: clean
clean:
ifneq ($(wildcard $(KDIR)),)
# Clean kernel module only when KDIR is valid
	$(MAKE) -C $(KDIR) M=$(PWD)/core clean
	$(MAKE) -C $(KDIR) M=$(PWD)/recipes clean
endif
	$(MAKE) -C $(PWD)/lib clean
	$(MAKE) -C $(PWD)/tools clean

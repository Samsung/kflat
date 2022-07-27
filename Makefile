# Samsung R&D Poland - Mobile Security Group

PWD := $(shell pwd)
KDIR ?= $(KERNEL_DIR)
CCDIR ?= $(CLANG_DIR)


ifeq ($(ARCH),arm64)

export CROSS_COMPILE := aarch64-linux-gnu-
export CXX := aarch64-linux-gnu-g++
export CC := $(CCDIR)/bin/clang.real
export CFLAGS := "--target=aarch64-linux-gnu --prefix=aarch64-linux-gnu-"
export LD := $(CCDIR)/bin/ld.lld

else ifeq ($(ARCH),x86_64)

export CC := $(CCDIR)/bin/clang.real
export LD := $(CCDIR)/bin/ld.lld
export CXX := g++

else
$(error "Unsupported architecture")
endif

default:
	$(MAKE) -C $(KDIR) M=$(PWD)/core CC=$(CC) LD=$(LD) CFLAGS=$(CFLAGS) modules
	$(MAKE) -C $(KDIR) M=$(PWD)/recipes CC=$(CC) LD=$(LD) CFLAGS=$(CFLAGS) modules
	$(MAKE) -C $(PWD)/lib all
	$(MAKE) -C $(PWD)/tools all

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/core clean
	$(MAKE) -C $(KDIR) M=$(PWD)/recipes clean
	$(MAKE) -C $(PWD)/lib clean
	$(MAKE) -C $(PWD)/tools clean

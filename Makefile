PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD)/core modules
	$(MAKE) -C $(KDIR) M=$(PWD)/recipes modules
	$(MAKE) -C $(PWD)/lib all
	$(MAKE) -C $(PWD)/tools all

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/core clean
	$(MAKE) -C $(KDIR) M=$(PWD)/recipes clean
	$(MAKE) -C $(PWD)/lib clean
	$(MAKE) -C $(PWD)/tools clean

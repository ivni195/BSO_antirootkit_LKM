KDIR := /lib/modules/$(shell uname -r)/build

# Module
obj-m := antirootkit.o

# Sources
antirootkit-objs := src/core.o src/check_sys_calls.o src/memory_prot.o src/utils.o src/checks.o src/check_hidden.o

ccflags-y := -I$(PWD)/include

# Recipes
all:
	$(MAKE) -C $(KDIR) M=$(PWD) SUBDIRS=$(PWD) modules

load:
	insmod antirootkit.ko

unload:
	rmmod antirootkit.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
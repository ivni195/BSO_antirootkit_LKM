KDIR := /lib/modules/$(shell uname -r)/build

# Module
obj-m := rootkit.o

# Sources
rootkit-objs := src/rootkit.o src/memory_prot.o src/my_syscalls.o
rootkit-objs += src/utils.o src/hide_module.o src/ftrace_utils.o

ccflags-y := -I$(PWD)/include

# Recipes
all:
	$(MAKE) -C $(KDIR) M=$(PWD) SUBDIRS=$(PWD) modules

load:
	insmod rootkit.ko

unload:
	rmmod rootkit.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
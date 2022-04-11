KDIR := /lib/modules/$(shell uname -r)/build

# Module
obj-m := antirootkit.o

# Sources
antirootkit-objs := src/core.o src/check_sys_calls.o src/check_ftrace_hooks.o
antirootkit-objs += src/utils.o src/checks.o src/check_hidden.o src/ftrace_utils.o
antirootkit-objs += src/sysfs_if.o src/check_entry_syscall.o src/check_idt.o

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
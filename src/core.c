#include <linux/init.h>     // __init and __exit
#include <linux/module.h>   // For loading LKM into the kernel
#include <linux/kernel.h>   // Types, macros, functions for the kernel
#include <linux/kallsyms.h> // Contains kallsysm_lookup_name function
#include <linux/unistd.h>   // Syscalls numbers
#include <linux/slab.h>     // Allocate/free kernel memory
#include <linux/dirent.h>
#include "utils.h"
#include "check_sys_calls.h"
#include "checks.h"

// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jakub Pilimon");
MODULE_DESCRIPTION("Antirootkit LKM.");
MODULE_VERSION("1.0");




static int __init anti_rk_init(void) {
    printk(INFO("Initializing..."));

//    Setup all checks
    if(!setup_checks()){
        printk(WARNING("Checks setup failed."));
        return 1;
    }

    checks_run();

    return 0;
}


static void __exit anti_rk_exit(void) {
    checks_run();
    cleanup_checks();
    printk(INFO("Cleanup done. Exiting..."));
}

module_init(anti_rk_init);
module_exit(anti_rk_exit);

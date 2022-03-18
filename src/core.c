#include <linux/init.h>     // __init and __exit
#include <linux/module.h>   // For loading LKM into the kernel
#include <linux/kernel.h>   // Types, macros, functions for the kernel
#include "utils.h"
#include "checks.h"
#include "ftrace_utils.h"


// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jakub Pilimon");
MODULE_DESCRIPTION("Antirootkit LKM.");
MODULE_VERSION("1.0");

pt_regs_t orig_kill;

asmlinkage unsigned long my_kill(const struct pt_regs *regs) {
    int sig = regs->si;
    pid_t pid = regs->di;
    char pid_str[NAME_MAX];

    return orig_kill(regs);
}

static void get_func_assembly(char *ptr){
    char bytes[601];
    int i;

    memzero_explicit(bytes, 601);

    for(i = 0; i < 300; i++){
        sprintf(bytes, "%s%02hhX", bytes, ptr[i]);
    }
    printk("%s\n", bytes);
}

struct ftrace_hook hooks[] = {
        HOOK("__x64_sys_kill", my_kill, &orig_kill),
};

typedef int (*core_kernel_text_t)(unsigned long addr);
typedef unsigned long (*ftrace_location_t)(unsigned long ip);
typedef struct dyn_ftrace *(*lookup_rec_t)(unsigned long start, unsigned long end);
typedef struct ftrace_func_entry *(*__ftrace_lookup_ip_t)(struct ftrace_hash *hash, unsigned long ip);
typedef unsigned long (*ftrace_get_addr_curr_t)(struct dyn_ftrace *rec);

static int __init anti_rk_init(void) {
    RK_INFO("Initializing...");
    if (!find_kallsyms_lookup_name()){
        RK_WARNING("Failed looking up kallsyms_lookup_name.");
        return 1;
    }
//    Setup all checks
    if(!setup_checks()){
        RK_WARNING("Checks setup failed.");
        return 1;
    }

    fh_install_hook(&hooks[0]);

    checks_run();

    return 0;
}


static void __exit anti_rk_exit(void) {
//    checks_run();
    fh_remove_hook(&hooks[0]);
    cleanup_checks();
    RK_INFO("Cleanup done. Exiting...");
}

module_init(anti_rk_init);
module_exit(anti_rk_exit);

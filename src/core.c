#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sort.h>

#include "checks.h"
#include "ftrace_utils.h"
#include "sysfs_if.h"
#include "utils.h"


// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jakub Pilimon");
MODULE_DESCRIPTION("Antirootkit LKM.");
MODULE_VERSION("1.0");

pt_regs_t orig_kill;

asmlinkage unsigned long my_kill(const struct pt_regs *regs) {
    return orig_kill(regs);
}


struct ftrace_hook hooks[] = {
        HOOK("__x64_sys_kill", my_kill, &orig_kill),
};


static int __init anti_rk_init(void) {
    RK_INFO("Initializing...");
    if (!find_kallsyms_lookup_name()) {
        RK_WARNING("Failed looking up kallsyms_lookup_name.");
        return 1;
    }

    if(!setup_util_funcs()){
        RK_WARNING("Failed looking up necessary functions.");
        return 1;
    }

    if (!setup_checks()) {
        RK_WARNING("Checks setup failed.");
        return 1;
    }

    user_if_kobj = kobject_create_and_add("antirk_sysfs_interface", kernel_kobj);
    if(!sysfs_create_file(user_if_kobj, &user_if_kattr.attr))
        RK_WARNING("Cannot create sysfs interface file.");

    fh_install_hook(&hooks[0]);

    checks_run();

    return 0;
}

static void __exit anti_rk_exit(void) {
//    checks_run();
    fh_remove_hook(&hooks[0]);
    kobject_put(user_if_kobj);
    cleanup_checks();
    RK_INFO("Cleanup done. Exiting...");
}

module_init(anti_rk_init);
module_exit(anti_rk_exit);

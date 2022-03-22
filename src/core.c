#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

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


static int foo;

static ssize_t foo_show(struct kobject *kobj, struct kobj_attribute *attr,
                        char *buf) {
    RK_INFO("FOO_SHOW!");
    return sprintf(buf, "%d\n", foo);
}

static ssize_t foo_store(struct kobject *kobj, struct kobj_attribute *attr,
                         const char *buf, size_t count) {
    RK_INFO("FOO_STORE!");
    sscanf(buf, "%du", &foo);
    return count;
}



//static  =__ATTR(foo, 0660, foo_show, foo_store);

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
    sysfs_create_file(user_if_kobj, &user_if_kattr.attr);

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

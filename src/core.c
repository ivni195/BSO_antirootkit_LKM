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
const unsigned long *module_addr_min, *module_addr_max;

asmlinkage unsigned long my_kill(const struct pt_regs *regs) {
    return orig_kill(regs);
}
struct mod_initfree {
    struct llist_node node;
    void *module_init;
};


struct ftrace_hook hooks[] = {
        HOOK("__x64_sys_kill", my_kill, &orig_kill),
};

static int comp(const void *a, const void *b){
    return *(unsigned long *) a > *(unsigned long *) b ? 1:-1;
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




bool check_string(char *s){
    int i = 0;
//    RK_INFO("---------------------------");

    if (s[0] == '\0')
        return false;

    while (s[i] != '\0' && i < MODULE_NAME_LEN){
        if(s[i] < 0x20 || s[i] >= 0x7e) {
            return false;
        }
        i++;
//        RK_INFO("%c", s[i]);
    }

    return true;
}


static bool is_within_mod_addr(unsigned long addr){
    return *module_addr_min <= addr && addr <= *module_addr_max;
}


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

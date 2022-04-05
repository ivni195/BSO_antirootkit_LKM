#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sort.h>
#include <linux/workqueue.h>

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

asmlinkage unsigned long my_kill(const struct pt_regs *regs)
{
        return orig_kill(regs);
}


struct ftrace_hook hooks[] = {
        HOOK("__x64_sys_kill", my_kill, &orig_kill),
};

void work_fn(struct work_struct *work);
DECLARE_DELAYED_WORK(periodic_checks_work, work_fn);
void work_fn(struct work_struct *work)
{
        rk_info("Running periodic CHECKS...");
        checks_run();
        schedule_delayed_work(&periodic_checks_work, __msecs_to_jiffies(2000));
}

static int __init anti_rk_init(void)
{
        rk_info("Initializing...");
        if (!find_kallsyms_lookup_name()) {
                rk_debug("Failed looking up kallsyms_lookup_name.");
                return -EINVAL;
        }

        if (!find_util_funcs()) {
                rk_debug("Failed looking up necessary functions.");
                return -EINVAL;
        }

        if (!setup_checks()) {
                rk_debug("Checks setup failed.");
                return -EINVAL;
        }

        user_if_kobj = kobject_create_and_add("antirk_sysfs_interface", kernel_kobj);
        if (sysfs_create_file(user_if_kobj, &user_if_kattr.attr) != 0)
                rk_debug("Cannot create sysfs interface file.");

        schedule_delayed_work(&periodic_checks_work, __msecs_to_jiffies(1000));
        fh_install_hook(&hooks[0]);


        checks_run();

        return 0;
}

static void __exit anti_rk_exit(void)
{
        //    checks_run();
        fh_remove_hook(&hooks[0]);
        kobject_put(user_if_kobj);
        cancel_delayed_work_sync(&periodic_checks_work);
        cleanup_checks();
        rk_info("Cleanup done. Exiting...");
}

module_init(anti_rk_init);
module_exit(anti_rk_exit);

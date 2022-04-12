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

// Periodic work that runs every x seconds
void periodic_work_fn(struct work_struct *work);
DECLARE_DELAYED_WORK(do_checks_work, periodic_work_fn);
void periodic_work_fn(struct work_struct *work)
{
	rk_info("Running scheduled CHECKS...");
	checks_run();
	schedule_delayed_work(&do_checks_work,
			      __msecs_to_jiffies(PERIODIC_CHECK_INTERVAL));
}

// A work that is schedule whenever kallsyms_lookup_name is called.
void hook_work_fn(struct work_struct *work);
DECLARE_DELAYED_WORK(do_hook_checks_work, hook_work_fn);
void hook_work_fn(struct work_struct *work)
{
	rk_info("Running hook CHECKS...");
#ifdef CHECK_FTRACE_HOOKS
	check_ftrace_hooks();
#endif
#ifdef CHECK_SYS_CALL_HOOKS
	check_sys_call_hooks();
#endif
}

// Pointers to original functions (for ftrace hooks)
int (*orig_load_module)(struct load_info *info, const char __user *uargs,
			int flags);
unsigned long (*orig_kallsyms_lookup_name)(const char *name);

// Ftrace hook functions
int my_load_module(struct load_info *info, const char __user *uargs, int flags)
{
	int ret = orig_load_module(info, uargs, flags);
	rk_info("A module has just been loaded. Running CHECKS for hidden modules...");
	check_hidden_modules();
	return ret;
}

unsigned long my_kallsyms_lookup_name(const char *name)
{
	unsigned long ret;
	ret = orig_kallsyms_lookup_name(name);
	rk_info("kallsyms_lookup_name has just been called with argument %s - running CHECKS...",
		name);
	/*
	 * If something calls kallsys_lookup_name, it means that a rootkit
	 * might be looking for functions to hook.
	 */
	schedule_delayed_work(&do_hook_checks_work, __msecs_to_jiffies(100));

	return ret;
}

static struct ftrace_hook hooks[] = {
	HOOK("kallsyms_lookup_name", my_kallsyms_lookup_name,
	     &orig_kallsyms_lookup_name),
	HOOK("load_module", my_load_module, &orig_load_module),
};

static int __init anti_rk_init(void)
{
	rk_info("Initializing...");
	if (!find_kallsyms_lookup_name()) {
		rk_err("Failed looking up kallsyms_lookup_name.");
		return -EINVAL;
	}

	if (!find_util_symbols()) {
		rk_err("Failed looking up necessary functions.");
		return -EINVAL;
	}

	if (!setup_checks()) {
		rk_err("Checks setup failed.");
		return -EINVAL;
	}

	user_if_kobj =
		kobject_create_and_add("antirk_sysfs_interface", kernel_kobj);
	if (sysfs_create_file(user_if_kobj, &user_if_kattr.attr) != 0)
		rk_err("Cannot create sysfs interface file.");

	schedule_delayed_work(&do_checks_work,
			      __msecs_to_jiffies(PERIODIC_CHECK_INTERVAL));

	if (fh_install_hooks(hooks, ARRAY_SIZE(hooks)) != 0) {
		rk_err("Failed inserting ftrace hooks.");
		return -EINVAL;
	}

	checks_run();

	return 0;
}

static void __exit anti_rk_exit(void)
{
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	kobject_put(user_if_kobj);
	cancel_delayed_work_sync(&do_checks_work);
	cancel_delayed_work_sync(&do_hook_checks_work);
	cleanup_checks();
	rk_info("Cleanup done. Exiting...");
}

module_init(anti_rk_init) module_exit(anti_rk_exit)

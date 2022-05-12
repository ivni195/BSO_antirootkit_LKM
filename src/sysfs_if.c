#include "sysfs_if.h"

ssize_t run_checks_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	if (buf[0] == '0') {
		rk_warning("Running CHECKS on user's demand.");
		checks_run();
	} else {
		rk_info("Write '0' to trigger CHECKS.");
	}

	return (ssize_t)count;
}

struct kobject *user_if_kobj;
struct kobj_attribute user_if_kattr = __ATTR_WO(run_checks);

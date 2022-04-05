#include "sysfs_if.h"

struct kobject *user_if_kobj;
struct kobj_attribute user_if_kattr =
	__ATTR(run_checks, 0660, kobj_show, kobj_store);

ssize_t kobj_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0\n");
}

ssize_t kobj_store(struct kobject *kobj, struct kobj_attribute *attr,
		   const char *buf, size_t count)
{
	rk_warning("Running CHECKS on user's demand.");
	checks_run();
	return (ssize_t)count;
}
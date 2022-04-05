#ifndef BSO_ANTIROOTKIT_LKM_SYSFS_IF_H
#define BSO_ANTIROOTKIT_LKM_SYSFS_IF_H

#include "checks.h"

extern struct kobject *user_if_kobj;
extern struct kobj_attribute user_if_kattr;

ssize_t kobj_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);

ssize_t kobj_store(struct kobject *kobj, struct kobj_attribute *attr,
		   const char *buf, size_t count);

#endif //BSO_ANTIROOTKIT_LKM_SYSFS_IF_H

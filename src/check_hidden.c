#include "check_hidden.h"


static bool contains(struct list_head *proc_list, struct kobject *kobj) {
    const char *kobj_name = kobj->name;
    struct list_head *p, *tmp;
    struct module *mod;
    list_for_each_safe(p, tmp, proc_list) {
        mod = container_of(p, struct module, list);
        if (strncmp(kobj_name, mod->name, strlen(kobj_name)) == 0)
            return true;
    }
    return false;
}


void compare_modules(void) {
    struct list_head *p_sys, *tmp;
    struct kobject *kobj;
    struct kset *kset = __this_module.mkobj.kobj.kset;
    bool hidden_any = false;

//    Modules can be removed during iteration
    list_for_each_safe(p_sys, tmp, &kset->list) {
        kobj = container_of(p_sys, struct kobject, entry);
        if (atomic_read(&kobj->kref.refcount.refs) > 2) {
            if (!contains(THIS_MODULE->list.prev, kobj)) {
                hidden_any = true;
                RK_WARNING("Looks like %s module is hidden (present in sysfs, not present in procfs).", kobj->name);
            }
        }
    }


    if (!hidden_any) {
        RK_INFO("No hidden modules found.");
    }

}


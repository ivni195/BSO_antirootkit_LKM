#include "check_hidden.h"

static char *procfs_modules[255];
static char *sysfs_modules[255];
static int n_procfs = 0, n_sysfs = 0;

bool scan_procfs(void){
    struct module *mod;
    struct list_head *p;

//    start from prev so we don't skip the antirootkit module
    list_for_each(p, __this_module.list.prev){
        mod = list_entry(p, struct module, list);
        procfs_modules[n_procfs++] = mod->name;
        if(n_procfs == 255){
            printk(WARNING("Procfs entry buffer is full. Some modules may be skipped."));
            return false;
        }
    }
    return true;
}

bool scan_sysfs(void){
    struct list_head *p;
    struct kobject *kobj;
    struct kset *kset = __this_module.mkobj.kobj.kset;

    list_for_each(p, &kset->list) {
        kobj = container_of(p, struct kobject, entry);
//        DOPYTAC DLACZEGO TU JEST 2
        if(atomic_read(&kobj->kref.refcount.refs) >  2){
            sysfs_modules[n_sysfs++] = kobj->name;
        }
        if(n_sysfs == 255) {
            printk(WARNING("Sysfs entry buffer is full. Some modules may be skipped."));
            return false;
        }
    }
    return true;
}

void compare_fs(void){
    int i, j;
    bool found;
    char *sysfs_name;

    for(i = 0; i < n_sysfs; i++){
        found = false;
        sysfs_name = sysfs_modules[i];
        for(j = 0; j < n_procfs; j++){
            if(strncmp(sysfs_name, procfs_modules[j], strlen(sysfs_name)) == 0){
                found = true;
                break;
            }
        }
        if (!found){
            printk(WARNING("Looks like %s module is hidden (present in sysfs, not present in procfs)."), sysfs_name);
        }
    }

}

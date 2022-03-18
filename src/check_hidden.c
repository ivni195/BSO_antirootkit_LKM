#include "check_hidden.h"

#define MAX_MODULES 512

static char **procfs_modules;
static char **sysfs_modules;
static int n_procfs = 0, n_sysfs = 0;

bool setup_check_hidden(void){
    procfs_modules = kzalloc(MAX_MODULES * sizeof(char *), GFP_KERNEL);
    sysfs_modules = kzalloc(MAX_MODULES * sizeof(char *), GFP_KERNEL);

    return (procfs_modules != NULL) && (sysfs_modules != NULL);
}

bool scan_procfs(void){
    struct module *mod;
    struct list_head *p;

//    start from prev, so we don't skip the antirootkit module
    list_for_each(p, __this_module.list.prev){
        mod = list_entry(p, struct module, list);
        procfs_modules[n_procfs++] = mod->name;
        if(n_procfs == MAX_MODULES){
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
        if(atomic_read(&kobj->kref.refcount.refs) >  2){
            sysfs_modules[n_sysfs++] = kobj->name;
        }
        if(n_sysfs == MAX_MODULES) {
            return false;
        }
    }
    return true;
}

void compare_modules(void){
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
            RK_WARNING("Looks like %s module is hidden (present in sysfs, not present in procfs).", sysfs_name);
        }
    }

}

void cleanup_check_hidden(void){
    kfree(sysfs_modules);
    kfree(procfs_modules);
}

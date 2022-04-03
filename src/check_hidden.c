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


void compare_proc_sys(void) {
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
                RK_WARNING("Looks like \"%s\" module is hidden (present in sysfs, not present in procfs).", kobj->name);
            }
        }
    }


    if (!hidden_any) {
        RK_INFO("No hidden modules found.");
    }
}


void signature_scan_memory(void) {
//    Start and end of the module memory range.
    unsigned long module_addr_min;
    unsigned long module_addr_max;

    void *ptr;
    struct module *ptr_mod;
//    You can find these offsets (they are relative to RIP) after disassembling the __module_address function.
    module_addr_min = *(unsigned long *) ((void *) module_addr_ + 0x1ca3b18);
    module_addr_max = *(unsigned long *) ((void *) module_addr_ + 0x1ca3b20);

    ptr = (void *) module_addr_min;

    while ((unsigned long) ptr < module_addr_max) {
        ptr_mod = (struct module *) ptr;

//        Make sure we're looking at valid addresses. Check the first and the last address of the potential module struct.
        if (kern_addr_valid_((unsigned long) ptr_mod) &&
            kern_addr_valid_((unsigned long) ptr_mod + sizeof(struct module))) {
//            Check the struct module signature.
            if ((ptr_mod->state == MODULE_STATE_LIVE || ptr_mod->state == MODULE_STATE_COMING) &&
                ptr_mod == ptr_mod->mkobj.mod) {
//                We found a valid module - now let's check if it's in the module list
                if(lookup_module_by_name(ptr_mod->name) == NULL){
                    RK_WARNING("Looks like the \"%s\" module is hidden (found by a memory scan).", ptr_mod->name);
                }
            }
        }
        ptr += 0x10;
    }
}




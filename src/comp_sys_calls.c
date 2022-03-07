#include "comp_sys_calls.h"



void find_sys_call_table_addr(void) {
//    Create kernel probe and set kp.symbol_name to the desired function
    struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
    };
//    Create a function pointer that will later store the desired address
    kallsyms_lookup_name_t kallsyms_lookup_name;
//    Register kprobe, so it searches for the symbol given by kp.symbol_name
    register_kprobe(&kp);
//    Retrieve address
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
//    Now we can unregister kprobe and return the pointer to sys_call_table
    unregister_kprobe(&kp);
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
}

int save_sys_call_table(void){
    int i;
    sys_call_table_saved = kzalloc(sizeof(unsigned long) * __NR_syscall_max, GFP_KERNEL);
    if(sys_call_table_saved == NULL || sys_call_table == NULL)
        return 1;

    for (i = 0; i < __NR_syscall_max; i++) {
        sys_call_table_saved[i] = sys_call_table[i];
    }

    return 0;
}

int compare_sys_call_table(void){
    int i;
    int changed = 0;
    char buff[255];

    printk(INFO("Looking for hooks in sys_call_table..."));

    for (i = 0; i < __NR_syscall_max; ++i) {
        if(IS_ENTRY_HOOKED(i)){
            sprint_symbol(buff, sys_call_table_saved[i]);
            printk(WARNING("Looks like %s has been hooked.\nThe address should be: 0x%p\nbut instead it is: 0x%p"),
                   buff, (void *) sys_call_table_saved[i], (void *) sys_call_table[i]);
            changed = 1;
        }
    }

    printk(INFO("Finished looking for hooks."));

    return changed;
}

void restore_sys_call_table(void){
    int i;
    disable_memory_protection();

    for (i = 0; i < __NR_syscall_max; ++i) {
        sys_call_table[i] = sys_call_table_saved[i];
    }

    enable_memory_protection();
}

void cleanup_sys_call_table(void){
    kfree(sys_call_table_saved);
}

#include "check_sys_calls.h"

typedef int (*core_kernel_text_t)(unsigned long addr);

static core_kernel_text_t core_kernel_text_;

// The actual one
static unsigned long *sys_call_table;
// The backup one
static unsigned long *sys_call_table_saved;
static long *non_core_addrs;
static int n;

kallsyms_lookup_name_t kallsyms_lookup_name_;

static const char *get_name(long nr){
    switch (nr){
        case __NR_kill:
            return "__x64_sys_kill";
        case __NR_getdents64:
            return "__x64_sys_getdents64";
        default:
            return NULL;
    }
}

bool setup_sys_call_check(void) {
//    Create kernel probe and set kp.symbol_name to the desired function
    struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
    };
//    Register kprobe, so it searches for the symbol given by kp.symbol_name
    register_kprobe(&kp);
//    Retrieve address
    kallsyms_lookup_name_ = (kallsyms_lookup_name_t) kp.addr;
//    Now we can unregister kprobe and return the pointer to sys_call_table
    unregister_kprobe(&kp);

    if(kallsyms_lookup_name_ == NULL)
        return false;

    sys_call_table = (unsigned long *) kallsyms_lookup_name_("sys_call_table");
    save_sys_call_table();
    if (sys_call_table_saved == NULL)
        return false;


    core_kernel_text_ = (core_kernel_text_t) kallsyms_lookup_name_("core_kernel_text");

    non_core_addrs = kzalloc(sizeof(int) * __NR_syscall_max, GFP_KERNEL);

    return !(sys_call_table == NULL ||
           non_core_addrs == NULL ||
           core_kernel_text_ == NULL);
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
    long i;
    bool changed = false, backup_overwritten = false;
    char buff[255];
    n = 0;

    printk(INFO("Looking for hooks in sys_call_table..."));
    for (i = 0; i < __NR_syscall_max; ++i) {
        if(IS_ENTRY_HOOKED(i)){
            sprint_symbol(buff, sys_call_table_saved[i]);
            printk(WARNING("Looks like %s has been hooked.\nThe address should be: 0x%p\nbut instead it is: 0x%p"),
                   buff, (void *) sys_call_table_saved[i], (void *) sys_call_table[i]);
            changed = true;
        } else if(!core_kernel_text_(sys_call_table[i])){
            sprint_symbol(buff, sys_call_table_saved[i]);
            printk(WARNING("Looks like %s is not originated in the core kernel text section. (to zle, bardzo zle)"), buff);
            changed = true;
            backup_overwritten = true;
            non_core_addrs[n++] = i;
        }
    }

    printk(INFO("Finished looking for hooks."));

    if (changed && backup_overwritten){
        return 2;
    }
    else if(changed){
        return 1;
    }
    else{
        return 0;
    }
}

void restore_sys_call_table(int action) {
    int i;
    int k;
    unsigned long addr;
    const char *name;

    if(action == 1){
        // Recover from sys_call_table_saved
        disable_memory_protection();

        printk(WARNING("Syscall hooks found. Trying to recover..."));

        for (i = 0; i < __NR_syscall_max; ++i) {
            sys_call_table[i] = sys_call_table_saved[i];
        }

        enable_memory_protection();

        printk(INFO("Syscall table recovered."));
    }
    else if(action == 2){
        // Recover by looking up symbol names
        disable_memory_protection();
        printk(WARNING("Syscall hooks found. Backup entries point to hooks. Trying to recover by searching memory..."));

        for (k = 0; k < n; ++k) {
            name = get_name(non_core_addrs[k]);
            if (name == NULL) continue;
            addr = kallsyms_lookup_name_(name);
            if (addr == 0) continue;
            sys_call_table[non_core_addrs[k]] = addr;
            sys_call_table_saved[non_core_addrs[k]] = addr;
        }

        enable_memory_protection();
        printk(INFO("Syscall table recovered."));
    }
    else{
        printk(INFO("No syscall hooks found."));
    }
}

void cleanup_sys_call_table(void){
    kfree(non_core_addrs);
    kfree(sys_call_table_saved);
}

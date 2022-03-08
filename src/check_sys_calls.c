#include "check_sys_calls.h"

typedef int (*in_gate_area_no_mm_t)(unsigned long addr);

static char *local_stext, *local_etext;
static in_gate_area_no_mm_t local_in_gate_area_no_mm;

// The actual one
static unsigned long *sys_call_table;
// The backup one
static unsigned long *sys_call_table_saved;

bool setup_sys_call_check(void) {
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

    if(kallsyms_lookup_name == NULL)
        return false;

    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
    save_sys_call_table();
    if (sys_call_table_saved == NULL)
        return false;

    // Setup pointers needed to reimplement is_kernel_text
    local_stext = (char *) kallsyms_lookup_name("_stext");
    local_etext = (char *) kallsyms_lookup_name("_etext");
    local_in_gate_area_no_mm = (in_gate_area_no_mm_t) kallsyms_lookup_name("in_gate_area_no_mm");

    return !(sys_call_table == NULL ||
           local_etext == NULL ||
           local_stext == NULL ||
           local_in_gate_area_no_mm == NULL);
}

static int local_is_kernel_text(unsigned long addr){
    if ((addr >= (unsigned long)local_stext && addr <= (unsigned long)local_etext) ||
        arch_is_kernel_text(addr))
        return 1;
    return local_in_gate_area_no_mm(addr);
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
        if(!local_is_kernel_text(sys_call_table[i])){
            sprint_symbol(buff, sys_call_table_saved[i]);
            printk(WARNING("Looks like %s is not originated in the core kernel text section. (to zle, bardzo zle)"), buff);
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

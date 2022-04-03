#include "check_entry_syscall.h"

static unsigned long saved_entry_syscall;

bool setup_entry_syscall_check(void){
    rdmsrl(MSR_LSTAR, saved_entry_syscall);
    if(!core_kernel_text_(saved_entry_syscall)){
        RK_WARNING("Syscall entry location is not originated in the core kernel text area.");
        saved_entry_syscall = kallsyms_lookup_name_("entry_SYSCALL_64");
        if (saved_entry_syscall == 0){
            return false;
        }
    }
    return true;
}


int compare_entry_syscall(void){
    unsigned long curr_entry_syscall;
    rdmsrl(MSR_LSTAR, curr_entry_syscall);

    if (curr_entry_syscall != saved_entry_syscall){
        return 1;
    }
    return 0;
}


void restore_entry_syscall(int action){
    struct module *mod;
    unsigned long curr_entry_syscall;

    if (action == 0){
        RK_INFO("Syscall entry location is OK.");
    }
    else if(action == 1){
        RK_WARNING("Syscall entry location is not what it should be.");

        rdmsrl(MSR_LSTAR, curr_entry_syscall);
        mod = module_addr_(curr_entry_syscall);

        if(mod != NULL){
            RK_WARNING("Looks like the entry address belongs to module %s.", mod->name);
        }
    }
}

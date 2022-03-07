#include "checks.h"

bool setup_checks(void){
#ifdef CHECK_SYS_CALL_HOOKS
    find_sys_call_table_addr();
    if (sys_call_table == NULL){
        printk(WARNING("sys_call_table lookup failed."));
        return false;
    }

    save_sys_call_table();

    if (sys_call_table_saved == NULL){
        printk(WARNING("sys_call_table backup failed."));
        return false;
    }
    printk(INFO("Sys call hooks check setup succesfully."));
#endif

    return true;
}

void cleanup_checks(void){
#ifdef CHECK_SYS_CALL_HOOKS
    if (sys_call_table_saved != NULL)
        cleanup_sys_call_table();
#endif
}

void check_sys_call_hooks(void){
    int changed = compare_sys_call_table();
    if (changed){
        printk(WARNING("Some sys_call_table entries has been modified.\nRestoring original entries..."));
        restore_sys_call_table();
    }
    else{
        printk(INFO("No hooks found."));
    }
}

void check_MP_bit(void){
    if (IS_MP_BIT_SET){
        printk(INFO("MP bit is set (as it should be)."));
    }
    else{
        printk(WARNING("MP bit is cleared. Looks like someone has messed with the cr0 register.\nSetting MP bit back..."));
        enable_memory_protection();
    }
}

void checks_run(void){
#ifdef CHECK_SYS_CALL_HOOKS
    check_sys_call_hooks();
#endif
#ifdef CHECK_MP_BIT
    check_MP_bit();
#endif
}


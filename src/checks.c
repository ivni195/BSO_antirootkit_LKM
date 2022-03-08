#include "checks.h"

bool setup_checks(void){
#ifdef CHECK_SYS_CALL_HOOKS
    if(!setup_sys_call_check()){
        printk(WARNING("Sys call hooks check setup failed."));
        return false;
    }

    printk(INFO("Sys call hooks check setup succesfully."));
#endif

    return true;
}

void cleanup_checks(void){
#ifdef CHECK_SYS_CALL_HOOKS
    cleanup_sys_call_table();
#endif
}

void check_sys_call_hooks(void){
    int action = compare_sys_call_table();
    restore_sys_call_table(action);
}

void check_WP_bit(void){
    if (IS_WP_BIT_SET){
        printk(INFO("WP bit is set (as it should be)."));
    }
    else{
        printk(WARNING("WP bit is cleared (it should be set).\nSetting WP bit back..."));
        enable_memory_protection();
    }
}

void checks_run(void){
#ifdef CHECK_SYS_CALL_HOOKS
    check_sys_call_hooks();
#endif
#ifdef CHECK_WP_BIT
    check_WP_bit();
#endif
}


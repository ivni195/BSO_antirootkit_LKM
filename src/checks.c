#include "checks.h"

bool setup_checks(void){
#ifdef CHECK_SYS_CALL_HOOKS
    if(!setup_sys_call_check()){
        printk(WARNING("Sys call hooks check setup failed."));
        return false;
    }

    printk(INFO("Sys call hooks check setup succesfully."));
#endif

#ifdef CHECK_HIDDEN_MODULES
    if(!setup_check_hidden()){
        printk(WARNING("Hidden module check setup failed."));
        return false;
    }

    printk(INFO("Hidden module check setup succesfully."));
#endif

    return true;
}

void cleanup_checks(void){
#ifdef CHECK_SYS_CALL_HOOKS
    cleanup_sys_call_table();
#endif

#ifdef CHECK_HIDDEN_MODULES
    cleanup_check_hidden();
#endif
}


static void check_hidden_modules(void){
    if(!(scan_sysfs() && scan_procfs())){
        printk(WARNING("Scanning procfs/sysfs failed."));
        return;
    }

    printk(INFO("Scanning procfs/sysfs succeded. Comparing..."));

    compare_modules();
}

static void check_sys_call_hooks(void){
    int action = compare_sys_call_table();
    restore_sys_call_table(action);
}

static void check_WP_bit(void){
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
#ifdef CHECK_HIDDEN_MODULES
    check_hidden_modules();
#endif
}

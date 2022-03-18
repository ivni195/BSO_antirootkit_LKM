#include "checks.h"

bool setup_checks(void){
#ifdef CHECK_SYS_CALL_HOOKS
    if(!setup_sys_call_check()){
        RK_WARNING("Sys call hooks check setup failed.");
        return false;
    }

    RK_INFO("Sys call hooks check setup succesfully.");
#endif

#ifdef CHECK_HIDDEN_MODULES
    if(!setup_check_hidden()){
        RK_WARNING("Hidden module check setup failed.");
        return false;
    }

    RK_INFO("Hidden module check setup succesfully.");
#endif

#ifdef CHECK_FTRACE_HOOKS
    if(!setup_ftrace_hooks_check()){
        RK_WARNING("Ftrace hook check setup failed.");
        return false;
    }

    RK_INFO("Ftrace hook check setup succesfully.");
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
        RK_WARNING("Scanning procfs/sysfs failed.");
        return;
    }

    RK_INFO("Scanning procfs/sysfs succeded. Comparing...");

    compare_modules();
}

static void check_sys_call_hooks(void){
    int action = compare_sys_call_table();
    restore_sys_call_table(action);
}

static void check_WP_bit(void){
    if (IS_WP_BIT_SET){
        RK_INFO("WP bit is set (as it should be).");
    }
    else{
        RK_WARNING("WP bit is cleared (it should be set).\nSetting WP bit back...");
        enable_memory_protection();
    }
}

static void check_ftrace_hooks(void){
    scan_for_ftr_calls();
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
#ifdef CHECK_FTRACE_HOOKS
    check_ftrace_hooks();
#endif
}

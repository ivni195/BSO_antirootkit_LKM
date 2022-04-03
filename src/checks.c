#include "checks.h"

bool setup_checks(void) {
    RK_WARNING("Running CHECKS SETUP...");
#ifdef CHECK_SYS_CALL_HOOKS
    if(!setup_sys_call_check()){
        RK_WARNING("Sys call hooks check setup failed.");
        return false;
    }
#endif


#ifdef CHECK_FTRACE_HOOKS
    if(!setup_ftrace_hooks_check()){
        RK_WARNING("Ftrace hook check setup failed.");
        return false;
    }
#endif

#ifdef CHECK_ENTRY_SYSCALL
    if(!setup_entry_syscall_check()){
        RK_WARNING("Entry syscall check setup failed.");
        return false;
    }
#endif

    return true;
}

void cleanup_checks(void) {
#ifdef CHECK_SYS_CALL_HOOKS
    cleanup_sys_call_table();
#endif
}


static void check_hidden_modules(void) {
    RK_WARNING("Running HIDDEN MODULES CHECK...");
    compare_proc_sys();
    signature_scan_memory();
}

static void check_sys_call_hooks(void) {
    int action;
    RK_WARNING("Running SYSCALL HOOKS CHECK...");
    action = compare_sys_call_table();
    restore_sys_call_table(action);
}

static void check_WP_bit(void) {
    RK_WARNING("Running WP BIT CHECK...");
    if (IS_WP_BIT_SET) {
        RK_INFO("WP bit is set (as it should be).");
    } else {
        RK_WARNING("WP bit is cleared (it should be set).\nSetting WP bit back...");
        enable_memory_protection();
    }
}

static void check_ftrace_hooks(void) {
    RK_WARNING("Running FTRACE HOOKS CHECK...");
    scan_for_ftr_calls();
}

static void check_entry_syscall(void){
    int action;
    RK_WARNING("Running ENTRY SYSCALL CHECK...");
    action = compare_entry_syscall();
    restore_entry_syscall(action);
}

void checks_run(void) {
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
#ifdef CHECK_ENTRY_SYSCALL
    check_entry_syscall();
#endif
    RK_WARNING("Finished running CHECKS.");
}

#include "checks.h"

bool setup_checks(void)
{
	rk_info("Running CHECKS SETUP...");
#ifdef CHECK_SYS_CALL_HOOKS
	if (!setup_sys_call_check()) {
		rk_warning("Sys call hooks check setup failed.");
		return false;
	}
#endif

#ifdef CHECK_FTRACE_HOOKS
	if (!setup_ftrace_hooks_check()) {
		rk_warning("Ftrace hook check setup failed.");
		return false;
	}
#endif

#ifdef CHECK_ENTRY_SYSCALL
	if (!setup_entry_syscall_check()) {
		rk_warning("Entry syscall check setup failed.");
		return false;
	}
#endif

#ifdef CHECK_IDT
	if (!setup_int_check()) {
		rk_warning("IDT check setup failed.");
		return false;
	}
#endif

	return true;
}

void cleanup_checks(void)
{
#ifdef CHECK_SYS_CALL_HOOKS
	cleanup_sys_call_table();
#endif
}

void check_hidden_modules(void)
{
	rk_info("Running HIDDEN MODULES CHECK...");
	compare_proc_sys();
	signature_scan_memory();
}

void check_sys_call_hooks(void)
{
	int action;
	rk_info("Running SYSCALL HOOKS CHECK...");
	action = compare_sys_call_table();
	restore_sys_call_table(action);
}

void check_WP_bit(void)
{
	rk_info("Running WP BIT CHECK...");
	if ((read_cr0() & WP_BIT) == WP_BIT) {
		rk_info("WP bit is set (as it should be).");
	} else {
		rk_warning(
			"WP bit is cleared (it should be set).\nSetting WP bit back...");
		enable_memory_protection();
	}
}

void check_ftrace_hooks(void)
{
	rk_info("Running FTRACE HOOKS CHECK...");
	scan_for_ftr_calls();
}

void check_entry_syscall(void)
{
	int action;
	rk_info("Running ENTRY SYSCALL CHECK...");
	action = compare_entry_syscall();
	restore_entry_syscall(action);
}

void check_idt(void)
{
	compare_idt();
}

void checks_run(void)
{
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
#ifdef CHECK_IDT
	check_idt();
#endif
	rk_info("Finished running CHECKS.");
	rk_info("------------------------");
}

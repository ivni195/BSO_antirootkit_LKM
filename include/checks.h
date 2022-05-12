#ifndef BSO_ANTIROOTKIT_LKM_CHECKS_H
#define BSO_ANTIROOTKIT_LKM_CHECKS_H

#include "check_entry_syscall.h"
#include "check_ftrace_hooks.h"
#include "check_hidden.h"
#include "check_sys_calls.h"
#include "check_idt.h"
#include "config.h"

bool setup_checks(void);
void cleanup_checks(void);

void checks_run(void);

void check_hidden_modules(void);
void check_sys_call_hooks(void);
void check_WP_bit(void);
void check_ftrace_hooks(void);
void check_entry_syscall(void);
void check_idt(void);

#endif //BSO_ANTIROOTKIT_LKM_CHECKS_H

#ifndef BSO_ANTIROOTKIT_LKM_CHECKS_H
#define BSO_ANTIROOTKIT_LKM_CHECKS_H

#include "check_entry_syscall.h"
#include "check_ftrace_hooks.h"
#include "check_hidden.h"
#include "check_sys_calls.h"
#include "check_wp_bit.h"
#include "config.h"

bool setup_checks(void);
void cleanup_checks(void);

void checks_run(void);

#endif //BSO_ANTIROOTKIT_LKM_CHECKS_H

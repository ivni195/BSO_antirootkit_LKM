//
// Created by jakub on 18.03.2022.
//

#ifndef BSO_ANTIROOTKIT_LKM_CHECK_FTRACE_HOOKS_H
#define BSO_ANTIROOTKIT_LKM_CHECK_FTRACE_HOOKS_H

#include "ftrace_utils.h"
#include "config.h"

bool setup_ftrace_hooks_check(void);
void scan_for_ftr_calls(void);

// no cleanup function needed


#endif //BSO_ANTIROOTKIT_LKM_CHECK_FTRACE_HOOKS_H

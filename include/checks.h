#ifndef BSO_ANTIROOTKIT_LKM_CHECKS_H
#define BSO_ANTIROOTKIT_LKM_CHECKS_H

#include "config.h"
#include "check_sys_calls.h"
#include "config.h"

bool setup_checks(void);
void cleanup_checks(void);

void check_sys_call_hooks(void);
void check_WP_bit(void);

void checks_run(void);

#endif //BSO_ANTIROOTKIT_LKM_CHECKS_H

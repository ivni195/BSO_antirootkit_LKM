#ifndef BSO_ANTIROOTKIT_LKM_CHECKS_H
#define BSO_ANTIROOTKIT_LKM_CHECKS_H

#include "config.h"
#include "check_sys_calls.h"
#include "check_hidden.h"

bool setup_checks(void);
void cleanup_checks(void);

void checks_run(void);

#endif //BSO_ANTIROOTKIT_LKM_CHECKS_H

#ifndef BSO_ANTIROOTKIT_LKM_CHECK_HIDDEN_H
#define BSO_ANTIROOTKIT_LKM_CHECK_HIDDEN_H

#include "utils.h"

bool setup_check_hidden(void);

// get modules from procfs perspective
bool scan_procfs(void);

// get modules from sysfs perspective
bool scan_sysfs(void);

// compare the two perspectives we got
void compare_modules(void);

void cleanup_check_hidden(void);

#endif //BSO_ANTIROOTKIT_LKM_CHECK_HIDDEN_H

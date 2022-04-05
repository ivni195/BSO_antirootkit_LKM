#ifndef BSO_ANTIROOTKIT_LKM_CHECK_HIDDEN_H
#define BSO_ANTIROOTKIT_LKM_CHECK_HIDDEN_H

#include "utils.h"

// compare the two perspectives we got
void compare_proc_sys(void);
// scan memory and search for a struct module signature
void signature_scan_memory(void);

#endif//BSO_ANTIROOTKIT_LKM_CHECK_HIDDEN_H

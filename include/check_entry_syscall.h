#ifndef BSO_ANTIROOTKIT_LKM_ENTRY_SYSCALL_CHECK_H
#define BSO_ANTIROOTKIT_LKM_ENTRY_SYSCALL_CHECK_H

#include "utils.h"

// Backup the MSR_LSTAR value
bool setup_entry_syscall_check(void);

/*
 * Compare the saved value with the one present in IA32_LSTAR MSR
 * Returns:
 *  0 if no change detected.
 *  1 if a change is detected
 */
int compare_entry_syscall(void);

// Restore IA32_LSTAR MSR
void restore_entry_syscall(int action);


#endif//BSO_ANTIROOTKIT_LKM_ENTRY_SYSCALL_CHECK_H

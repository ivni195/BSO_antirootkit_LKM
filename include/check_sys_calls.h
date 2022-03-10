#ifndef BSO_ANTIROOTKIT_LKM_CHECK_SYS_CALLS_H
#define BSO_ANTIROOTKIT_LKM_CHECK_SYS_CALLS_H
#include <linux/unistd.h>
#include "utils.h"
#include "memory_prot.h"

// Stuff for is_kernel_text




#define IS_ENTRY_HOOKED(i) sys_call_table_saved[(i)] != sys_call_table[(i)]

/*
 * Get the address of the sys_call_table by using kallsyms_lookup_name.
 */
bool setup_sys_call_check(void);

/*
 * Save the sys_call_table to a seperate array.
*/
int save_sys_call_table(void);

/*
 * Assuming our module was loaded before rootkit,
 * we can compare sys_call_table_saved with the actual one.
 * Even if a rootkit was loaded before,
 * we can compare symbol names of choosen sys calls
 * using sprint_symbol.
*/
int compare_sys_call_table(void);


/*
 * If we detected a hook, besides warning the user,
 * we can also restore the sys_call_table.
 * action = 0 -> no changes detected
 * action = 1 -> changes detected but recoverable from saved sys_call_table
 * action = 2 -> chenges detected but unrecoverable from saved sys_call_table, search the memory
 *      to find original syscalls
 */
void restore_sys_call_table(int action);

/*
 * Free the used memory.
 */
void cleanup_sys_call_table(void);

#endif //BSO_ANTIROOTKIT_LKM_CHECK_SYS_CALLS_H

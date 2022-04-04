#ifndef BSO_ANTIROOTKIT_LKM_CONFIG
#define BSO_ANTIROOTKIT_LKM_CONFIG

#include "utils.h"

/*
 * Config file that tells the module which checks should be performed.
 * Comment out checks that shouldn't be performed.
 */

//#define CHECK_SYS_CALL_HOOKS
//#define CHECK_ENTRY_SYSCALL
//#define CHECK_WP_BIT
#define CHECK_HIDDEN_MODULES
//#define CHECK_FTRACE_HOOKS


// Add modules that you want to whitelist
static const char whitelisted_mods[][MODULE_NAME_LEN] = {
        "antirootkit" // DO NOT REMOVE THIS ONE, THIS LKM HOOKS SOME FUNCTIONS USING FTRACE
};

/*
 * Add functions that you want to protect from ftrace hooking.
 * Only add fucntion that are compiled without "notrace".
 */
static const char protected_funcs[][KSYM_NAME_LEN] = {
        "__x64_sys_kill",
        "kallsyms_lookup_name"
};


#endif //BSO_ANTIROOTKIT_LKM_CONFIG
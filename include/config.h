/*
 * Config file that tells the module which checks should be performed.
 * Comment out checks that shouldn't be performed.
 */

#ifndef BSO_ANTIROOTKIT_LKM_CONFIG
#define BSO_ANTIROOTKIT_LKM_CONFIG

#include "utils.h"

#define CHECK_SYS_CALL_HOOKS
#define CHECK_WP_BIT
#define CHECK_HIDDEN_MODULES
#define CHECK_FTRACE_HOOKS

// MODIFY THIS VALUE TO MATCH THE NUMBER OF whitelisted_mods ENTRIES
static int n_whitelisted = 1;
static const char whitelisted_mods[][MODULE_NAME_LEN] = {
        "antirootkit" // DO NOT REMOVE THIS ONE, THIS LKM HOOKS SOME FUNCTIONS USING FTRACE
};

// MODIFY THIS VALUE TO MATCH THE NUMBER OF protected_funcs ENTRIES
static int n_protected_funcs = 1;
static const char protected_funcs[][KSYM_SYMBOL_LEN] = {
        "__x64_sys_kill"
};


#endif //BSO_ANTIROOTKIT_LKM_CONFIG
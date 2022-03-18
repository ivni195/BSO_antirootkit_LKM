/*
 * Hooking mechanism stolen from https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2.
 */

#ifndef BSO_ANTIROOTKIT_LKM_FTRACE_UTILS_H
#define BSO_ANTIROOTKIT_LKM_FTRACE_UTILS_H

#include <linux/ftrace.h>
#include "utils.h"

// Functions needed to find the ftrace hook.
typedef unsigned long (*ftrace_location_t)(unsigned long ip);
typedef struct dyn_ftrace *(*lookup_rec_t)(unsigned long start, unsigned long end);
typedef struct ftrace_func_entry *(*__ftrace_lookup_ip_t)(struct ftrace_hash *hash, unsigned long ip);
typedef unsigned long (*ftrace_get_addr_curr_t)(struct dyn_ftrace *rec);
typedef struct ftrace_ops *(*ftrace_find_tramp_ops_curr_t)(struct dyn_ftrace *rec);

/**
 * struct ftrace_hook    describes the hooked function
 *
 * @name:           the name of the hooked function
 *
 * @function:       the address of the wrapper function that will be called instead of
 *                     the hooked function
 *
 * @original:           a pointer to the place where the address
 *                     of the hooked function should be stored, filled out during installation of
 *             the hook
 *
 * @address:        the address of the hooked function, filled out during installation
 *             of the hook
 *
 * @ops:                ftrace service information, initialized by zeros;
 *                      initialization is finished during installation of the hook
 */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};


static const unsigned char nop[] = {
        0x0f, 0x1f, 0x44, 0x00, 0x00
};


// Helper macro to create ftrace_hook.
#define HOOK(_name, _function, _original)                    \
        {                                                    \
            .name = (_name),                                 \
            .function = (_function),                         \
            .original = (_original),                         \
        }

bool lookup_helper_funcs(void);
// tr_func - traced function
struct ftrace_ops *get_ftrace_ops(void *tr_func);
void inline *get_ftrace_callback(struct ftrace_ops *ops);

void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *ops, struct pt_regs *regs);
int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);


#endif //BSO_ANTIROOTKIT_LKM_FTRACE_UTILS_H

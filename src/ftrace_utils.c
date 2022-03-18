/*
 * Hooking mechanism stolen from https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2.
 */

#include "ftrace_utils.h"

lookup_rec_t lookup_rec_;
ftrace_find_tramp_ops_curr_t ftrace_find_tramp_ops_curr_;
ftrace_get_addr_curr_t ftrace_get_addr_curr_;
unsigned long tramp_size;

bool lookup_helper_funcs(void){
//    Call this function only after find_kallsyms_lookup_name
    lookup_rec_ = (lookup_rec_t) kallsyms_lookup_name_("lookup_rec");
    ftrace_find_tramp_ops_curr_ = (ftrace_find_tramp_ops_curr_t) kallsyms_lookup_name_("ftrace_find_tramp_ops_curr");
    ftrace_get_addr_curr_ = (ftrace_get_addr_curr_t) kallsyms_lookup_name_("ftrace_get_addr_curr");
    tramp_size = kallsyms_lookup_name_("ftrace_regs_caller_end") - kallsyms_lookup_name_("ftrace_regs_caller");

    return  lookup_rec_ != NULL &&
//            ftrace_find_tramp_ops_curr_ != NULL &&
            ftrace_get_addr_curr_ != NULL;
}

// Returns address to hook's ftrace_ops or NULL if NOP.
struct ftrace_ops *get_ftrace_ops(void *tr_func){
    struct dyn_ftrace *rec;
    char nop[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};
    unsigned long tramp;
    struct ftrace_ops **ops;

    if(memcmp(tr_func, nop, MCOUNT_INSN_SIZE) == 0){
        return NULL;
    }

    rec = lookup_rec_((unsigned long) tr_func, (unsigned long) tr_func);
    tramp = ftrace_get_addr_curr_(rec);
    ops = (struct ftrace_ops **) (tramp_size + 1 + tramp);
    return *ops;
}


void inline *get_ftrace_callback(struct ftrace_ops *ops){
    return ops->func;
}

/*
 * Insert addresses by resolving function name.
 */
static int resolve_hook_address(struct ftrace_hook *hook) {
        hook->address = kallsyms_lookup_name_(hook->name);

        if (!hook->address) {
                pr_debug("unresolved symbol: %s\n", hook->name);
                return -ENOENT;
        }

        // Jump over the ftrace call intruction.
        *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;

        return 0;
}


void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    /* Skip the function calls from the current module. */
//    if (!within_module(parent_ip, THIS_MODULE))
    regs->ip = (unsigned long) hook->function;
}

int fh_install_hook(struct ftrace_hook *hook)
{
    int err;

    err = resolve_hook_address(hook);
    if (err)
        return err;

    hook->ops.func = (ftrace_func_t) fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                      FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("register_ftrace_function() failed: %d\n", err);

        /* Don’t forget to turn off ftrace in case of an error. */
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
    }
}

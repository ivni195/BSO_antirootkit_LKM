#ifndef BSO_ANTIROOTKIT_LKM_UTILS_H
#define BSO_ANTIROOTKIT_LKM_UTILS_H

#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/dirent.h>

#define INFO(mess) KERN_INFO "antirootkit: " mess "\n"
#define WARNING(mess) KERN_WARNING "antirootkit: " mess "\n"

#define MP_BIT 0x10000
#define IS_MP_BIT_SET (read_cr0() & MP_BIT) == MP_BIT

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef asmlinkage unsigned long (*pt_regs_t)(const struct pt_regs *regs);


#endif //BSO_ANTIROOTKIT_LKM_UTILS_H

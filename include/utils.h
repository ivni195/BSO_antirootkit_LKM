#ifndef BSO_ANTIROOTKIT_LKM_UTILS_H
#define BSO_ANTIROOTKIT_LKM_UTILS_H

#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/dirent.h>

// For dmesg logging
#define RK_INFO(mess, ...) printk(KERN_INFO "antirootkit: " mess "\n", ##__VA_ARGS__)
#define RK_WARNING(mess, ...) printk(KERN_WARNING "antirootkit: " mess "\n", ##__VA_ARGS__)



#define NUM_PROTECTED_FUNCS (sizeof(protected_funcs) / KSYM_NAME_LEN)
#define NUM_WHITELISTED (sizeof(protected_funcs) / MODULE_NAME_LEN)

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

typedef asmlinkage unsigned long (*pt_regs_t)(const struct pt_regs *regs);

typedef int (*core_kernel_text_t)(unsigned long addr);

extern kallsyms_lookup_name_t kallsyms_lookup_name_;
extern core_kernel_text_t core_kernel_text_;

bool setup_util_funcs(void);

bool find_kallsyms_lookup_name(void);

bool is_module_text(struct module *mod, unsigned long addr);

struct module *lookup_module_by_name(const char *mod_name);

struct module *lookup_module_by_addr(unsigned long addr);

size_t string_array_size(char **tab, size_t string_size);

#endif //BSO_ANTIROOTKIT_LKM_UTILS_H

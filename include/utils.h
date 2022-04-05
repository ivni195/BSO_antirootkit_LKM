#ifndef BSO_ANTIROOTKIT_LKM_UTILS_H
#define BSO_ANTIROOTKIT_LKM_UTILS_H

//#include <linux/dirent.h>
#include <linux/kprobes.h>
#include <linux/slab.h>

// For dmesg logging
#define rk_info(mess, ...) printk(KERN_INFO "antirootkit: " mess "\n", ##__VA_ARGS__)
#define rk_warning(mess, ...) printk(KERN_WARNING "antirootkit: " mess "\n", ##__VA_ARGS__)
#define rk_debug(mess, ...) printk(KERN_DEBUG "antirootkit: " mess "\n", ##__VA_ARGS__)


#define NUM_PROTECTED_FUNCS (sizeof(protected_funcs) / KSYM_NAME_LEN)
#define NUM_WHITELISTED (sizeof(protected_funcs) / MODULE_NAME_LEN)

typedef asmlinkage unsigned long (*pt_regs_t)(const struct pt_regs *regs);

/*
 * The functions below are already declared in header files.
 * I append an underscore to avoid name conflicts.
 */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t kallsyms_lookup_name_;

typedef int (*core_kernel_text_t)(unsigned long addr);
extern core_kernel_text_t core_kernel_text_;

typedef struct module *(*module_address_t)(unsigned long addr);
extern module_address_t module_addr_;

typedef int (*kern_addr_valid_t)(unsigned long addr);
extern kern_addr_valid_t kern_addr_valid_;

bool find_util_funcs(void);

bool find_kallsyms_lookup_name(void);

bool is_module_addr(struct module *mod, unsigned long addr);

struct module *lookup_module_by_name(const char *mod_name);

#endif//BSO_ANTIROOTKIT_LKM_UTILS_H

#ifndef BSO_ANTIROOTKIT_LKM_UTILS_H
#define BSO_ANTIROOTKIT_LKM_UTILS_H

#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/dirent.h>

#define RK_INFO(mess, ...) printk(KERN_INFO "antirootkit: " mess "\n", ##__VA_ARGS__)
#define RK_WARNING(mess, ...) printk(KERN_WARNING "antirootkit: " mess "\n", ##__VA_ARGS__)

#define WP_BIT 0x10000
#define IS_WP_BIT_SET (read_cr0() & WP_BIT) == WP_BIT

#define NUM_PROTECTED_FUNCS (sizeof(protected_funcs) / KSYM_NAME_LEN)
#define NUM_WHITELISTED (sizeof(protected_funcs) / MODULE_NAME_LEN)

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef asmlinkage unsigned long (*pt_regs_t)(const struct pt_regs *regs);

extern kallsyms_lookup_name_t kallsyms_lookup_name_;

bool find_kallsyms_lookup_name(void);
bool is_module_text(struct module *mod, unsigned long addr);
struct module *lookup_module_by_name(const char *mod_name);
struct module *lookup_module_by_addr(unsigned long addr);
size_t string_array_size(char **tab, size_t string_size);

#endif //BSO_ANTIROOTKIT_LKM_UTILS_H

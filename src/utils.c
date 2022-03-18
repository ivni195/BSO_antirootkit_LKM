#include "utils.h"

kallsyms_lookup_name_t kallsyms_lookup_name_;

bool find_kallsyms_lookup_name(void) {
//    Create kernel probe and set kp.symbol_name to the desired function
    struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
    };
//    Create a function pointer that will later store the desired address
//    Register kprobe, so it searches for the symbol given by kp.symbol_name
    register_kprobe(&kp);
//    Retrieve address
    kallsyms_lookup_name_ = (kallsyms_lookup_name_t) kp.addr;
//    Now we can unregister kprobe and return the pointer to sys_call_table
    unregister_kprobe(&kp);

    return kallsyms_lookup_name_ != NULL;
}

struct module *lookup_module_by_name(const char *mod_name){
    struct list_head *p;
    struct module *mod;
    list_for_each(p, THIS_MODULE->list.prev){
        mod = list_entry(p, struct module, list);
        if (strncmp(mod_name, mod->name, strlen(mod_name)) == 0){
            return mod;
        }
    }
    return NULL;
}

bool is_module_text(struct module *mod, unsigned long addr) {
    unsigned long start;
    unsigned long end;

    start = (unsigned long) mod->core_layout.base;
    end = (unsigned long) (mod->core_layout.base + mod->core_layout.size);

    return (start <= addr && end >= addr);
}

struct module *lookup_module_by_addr(unsigned long addr){
    struct list_head *p;
    struct module *mod;
    list_for_each(p, THIS_MODULE->list.prev){
        mod = list_entry(p, struct module, list);
        if (is_module_text(mod, addr)){
            return mod;
        }
    }
    return NULL;
}



#include "check_ftrace_hooks.h"

static const unsigned char nop_5byte[] = {
        0x0f, 0x1f, 0x44, 0x00, 0x00
};

static bool is_mod_whitelisted(const char *name){
    int i;
    for(i = 0; i < NUM_WHITELISTED; i++){
        if (strncmp(name, whitelisted_mods[i], strlen(whitelisted_mods[i])) == 0)
            return true;
    }

    return false;
}

bool setup_ftrace_hooks_check(void){
    return lookup_helper_funcs();
}

void scan_for_ftr_calls(void){
    unsigned long i;
    const char *name;
    struct module *mod;
    void *func;
    struct ftrace_ops *ops;
    for(i = 0; i < NUM_PROTECTED_FUNCS; i++){
        name = protected_funcs[i];
        RK_INFO("Checking for ftrace hooks on %s.", name);
        func = kallsyms_lookup_name_(name);
        if(func == NULL){
            RK_WARNING("Failed looking up %s", name);
            continue;
        }
//        Skip if function is not hooked
        if (memcmp(func, nop_5byte, MCOUNT_INSN_SIZE) == 0){
            RK_INFO("Function %s is not hooked with ftrace.", name);
            continue;
        }
//        Get ftrace_ops by looking at the ftrace trampoline.
        ops = get_ftrace_ops(func);
        if(ops == NULL){
            RK_WARNING("Failed to lookup ftrace_ops for %s function hook.", name);
            continue;
        }

        mod = lookup_module_by_addr((unsigned long) ops->func);
        if(mod == NULL){
            RK_WARNING("Failed looking up owner module.");
        }
//        If we can't find module, we treat the module as hidden and remove the hook anyway.
        else if(is_mod_whitelisted(mod->name)){
            RK_WARNING("Function %s is hooked but the hooking module is whitelisted.", name);
            continue;
        }

//        If we got here, it means that the hook isn't whitelisted and is to be removed.
        RK_WARNING("Function %s is hooked and the hooking module is not whitelisted! Attempting to remove the hook.", name);
//        Remove hook
        if(unregister_ftrace_function(ops) != 0){
            RK_WARNING("Failed to unregister ftrace hook for %s function.", name);
        }
        else{
            RK_INFO("Hook removed succefully.");
        }

    }
}

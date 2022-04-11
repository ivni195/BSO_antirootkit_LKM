#include "utils.h"

kallsyms_lookup_name_t kallsyms_lookup_name_;
core_kernel_text_t core_kernel_text_;
module_address_t module_addr_;
kern_addr_valid_t kern_addr_valid_;

struct mutex *module_mutex_ptr;

bool find_kallsyms_lookup_name(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	//    Register kprobe, so it searches for the symbol given by kp.symbol_name
	register_kprobe(&kp);
	kallsyms_lookup_name_ = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);

	return kallsyms_lookup_name_ != NULL;
}

bool find_util_symbols(void)
{
	core_kernel_text_ =
		(core_kernel_text_t)kallsyms_lookup_name_("core_kernel_text");
	module_addr_ =
		(module_address_t)kallsyms_lookup_name_("__module_address");
	kern_addr_valid_ =
		(kern_addr_valid_t)kallsyms_lookup_name_("kern_addr_valid");

	module_mutex_ptr = (struct mutex *) kallsyms_lookup_name_("module_mutex");


	return core_kernel_text_ != NULL && module_addr_ != NULL &&
	       kern_addr_valid_ != NULL;
}

struct module *lookup_module_by_name(const char *mod_name)
{
	struct module *mod;

	list_for_each_entry_rcu(mod, &THIS_MODULE->list, list,
				 lockdep_is_held(module_mutex_ptr)) {
		if (strncmp(mod_name, mod->name, strlen(mod_name)) == 0) {
			return mod;
		}
	}
	return NULL;
}

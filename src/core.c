#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sort.h>

#include "checks.h"
#include "ftrace_utils.h"
#include "sysfs_if.h"
#include "utils.h"


// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jakub Pilimon");
MODULE_DESCRIPTION("Antirootkit LKM.");
MODULE_VERSION("1.0");

pt_regs_t orig_kill;
const unsigned long *module_addr_min, *module_addr_max;

asmlinkage unsigned long my_kill(const struct pt_regs *regs) {
    return orig_kill(regs);
}
struct mod_initfree {
    struct llist_node node;
    void *module_init;
};


struct ftrace_hook hooks[] = {
        HOOK("__x64_sys_kill", my_kill, &orig_kill),
};

static int comp(const void *a, const void *b){
    return *(unsigned long *) a > *(unsigned long *) b ? 1:-1;
}

static void get_func_assembly(char *ptr){
    char bytes[601];
    int i;

    memzero_explicit(bytes, 601);

    for(i = 0; i < 300; i++){
        sprintf(bytes, "%s%02hhX", bytes, ptr[i]);
    }
    printk("%s\n", bytes);
}




bool check_string(char *s){
    int i = 0;
//    RK_INFO("---------------------------");

    if (s[0] == '\0')
        return false;

    while (s[i] != '\0' && i < MODULE_NAME_LEN){
        if(s[i] < 0x20 || s[i] >= 0x7e) {
            return false;
        }
        i++;
//        RK_INFO("%c", s[i]);
    }

    return true;
}


static bool is_within_mod_addr(unsigned long addr){
    return *module_addr_min <= addr && addr <= *module_addr_max;
}


static int __init anti_rk_init(void) {
    int i, n_mods = 0;
    int ile=0;
    unsigned char noppp[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};
//    unsigned char test[] = {};



    unsigned long *start_addrs, *end_addrs, *struct_addrs;
    struct module *mod;
    struct list_head *p;
    void *ptr;
    struct module *ptr_mod;
    RK_INFO("Initializing...");
    if (!find_kallsyms_lookup_name()) {
        RK_WARNING("Failed looking up kallsyms_lookup_name.");
        return 1;
    }

    if(!setup_util_funcs()){
        RK_WARNING("Failed looking up necessary functions.");
        return 1;
    }

    if (!setup_checks()) {
        RK_WARNING("Checks setup failed.");
        return 1;
    }

    user_if_kobj = kobject_create_and_add("antirk_sysfs_interface", kernel_kobj);
    if(!sysfs_create_file(user_if_kobj, &user_if_kattr.attr))
        RK_WARNING("Cannot create sysfs interface file.");

    fh_install_hook(&hooks[0]);

    mod = THIS_MODULE;

    list_for_each(p, THIS_MODULE->list.prev){
        n_mods++;
    }
    p = &THIS_MODULE->list;

    start_addrs = kzalloc(n_mods * sizeof(unsigned long), GFP_KERNEL);
    end_addrs = kzalloc(n_mods * sizeof(unsigned long), GFP_KERNEL);
    struct_addrs = kzalloc(n_mods * sizeof(unsigned long), GFP_KERNEL);

    for (i = 0; i < 5; i++){
        mod = container_of(p, struct module, list);
        p = p->next;
        printk("%s from: %pK to %pK", mod->name, mod->core_layout.base, mod->core_layout.base + mod->core_layout.size);
    }
    i = 0;
    list_for_each(p, THIS_MODULE->list.prev){
        mod = container_of(p, struct module, list);
        start_addrs[i] = (unsigned long) mod->core_layout.base;
        end_addrs[i] = (unsigned long) (mod->core_layout.base + mod->core_layout.size);
        struct_addrs[i] = (unsigned long) mod;
        i++;
    }

    sort(start_addrs, n_mods, sizeof(unsigned long), &comp, NULL);
    sort(end_addrs, n_mods, sizeof(unsigned long), &comp, NULL);
    sort(struct_addrs, n_mods, sizeof(unsigned long), &comp, NULL);





    RK_INFO("%pK", kern_addr_valid_);

    module_addr_min = ((void *)module_addr_ + 0x1ca3b18);
    module_addr_max = ((void *)module_addr_ + 0x1ca3b20);
    ptr = (void *) *module_addr_min;

    while((unsigned long) ptr < *module_addr_max){
        ptr_mod = (struct module *) ptr;
        if(kern_addr_valid_((unsigned long) ptr_mod) && kern_addr_valid_((unsigned long) ptr_mod + sizeof(struct module))
//        && kern_addr_valid_((unsigned long) &ptr_mod->mkobj)
//        && kern_addr_valid_((unsigned long) &ptr_mod->init_layout)
//        && kern_addr_valid_((unsigned long) &ptr_mod->init_layout + sizeof(struct module_layout))
                ){
            if(
//                    check_string(ptr_mod->name) &&
                    (ptr_mod->state == MODULE_STATE_LIVE || ptr_mod->state == MODULE_STATE_COMING) &&
//                    is_within_mod_addr((unsigned long) ptr_mod->mkobj.mod) &&
//                    ((unsigned long) ptr_mod->init & 0xffffffff00000000) == 0xffffffff00000000 &&
//                    ptr_mod->init_layout.size == 0 && ptr_mod->init_layout.text_size == 0 &&
//                    ptr_mod->init_layout.ro_size == 0 && ptr_mod->init_layout.ro_after_init_size == 0 &&
//                    ptr_mod->init_layout.base == 0 &&
                    ptr_mod == ptr_mod->mkobj.mod
//                    ((unsigned long) ptr_mod->list.next & 0xffffffff00000000) == 0xffffffff00000000
//                    ptr_mod->core_layout.size >= (ptr_mod->core_layout.text_size + ptr_mod->core_layout.ro_size)
                    ){
                RK_INFO("%s", ptr_mod->name);
//                RK_INFO("%s", ptr_mod->version);
                RK_INFO("----------------------------");
                ile++;
            }
        }
//        if (ile == 10) break;
        ptr += 0x10;
    }
//    THIS_MODULE->mkobj.mod = (struct module *) 0xdeadbeef;
    RK_INFO("ile = %d", ile);
    RK_INFO("ile powinno = %d", n_mods);
    RK_INFO("czy = %d", check_string(noppp));

    ptr_mod = (struct module *) struct_addrs[10];
//    ptr_mod = THIS_MODULE;

//    RK_INFO("addr %pK", ptr_mod);
//    RK_INFO("list %pK", ptr_mod->list.prev);
//    RK_INFO("list in %d", is_within_mod_addr(ptr_mod->list.prev));
//    RK_INFO("num glp %pK", ptr_mod->num_gpl_syms);
//    RK_INFO("syms %pK", ptr_mod->syms);
//    RK_INFO("no inst text size %lx", ptr_mod->noinstr_text_size);
//
//
//    ptr_mod = lookup_module_by_name("rootkit");
//    if(ptr_mod){
//        RK_INFO("total init = %lx", ptr_mod->init_layout.size);
//        RK_INFO("text  init = %lx", ptr_mod->init_layout.text_size);
//        RK_INFO("ro    init = %lx", ptr_mod->init_layout.ro_size);
//        RK_INFO("ro ai init = %lx", ptr_mod->init_layout.ro_after_init_size);
//        RK_INFO("base  init = %lx", ptr_mod->init_layout.base);
//        RK_INFO("list next  = %lx", ptr_mod->list.next);
//        RK_INFO("kobj mod   = %lx", ptr_mod->mkobj.mod);
//        RK_INFO("mod        = %lx", ptr_mod);
//    }


//    ptr = __get_free_page(GFP_KERNEL);
//
//    RK_INFO("page alloced %pK", ptr);
//    RK_INFO("state %d", THIS_MODULE->state==MODULE_STATE_COMING);
//
//
//    free_page(ptr);
//
//    RK_INFO("init %pK", THIS_MODULE->init);
//    RK_INFO("core base %pK", THIS_MODULE->core_layout.base);
//    RK_INFO("init base %pK", THIS_MODULE->init_layout.base);
//    RK_INFO("init offset %pK", (void *) anti_rk_init - (void *) THIS_MODULE->init_layout.base);

    checks_run();

    return 0;
}

static void __exit anti_rk_exit(void) {
//    checks_run();
    fh_remove_hook(&hooks[0]);
    kobject_put(user_if_kobj);
    cleanup_checks();
    RK_INFO("Cleanup done. Exiting...");
}

module_init(anti_rk_init);
module_exit(anti_rk_exit);

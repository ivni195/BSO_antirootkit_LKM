#include "utils.h"


//unsigned long *setup_sys_call_check(void) {
////    Create kernel probe and set kp.symbol_name to the desired function
//    struct kprobe kp = {
//            .symbol_name = "kallsyms_lookup_name"
//    };
////    Create a function pointer that will later store the desired address
//    kallsyms_lookup_name_t kallsyms_lookup_name;
////    Register kprobe, so it searches for the symbol given by kp.symbol_name
//    register_kprobe(&kp);
////    Retrieve address
//    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
////    Now we can unregister kprobe and return the pointer to sys_call_table
//    unregister_kprobe(&kp);
//    return (unsigned long *) kallsyms_lookup_name("sys_call_table");
//}

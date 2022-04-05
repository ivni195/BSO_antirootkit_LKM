#include "memory_prot.h"

inline void force_write_cr0(unsigned long val)
{
        asm volatile(
                "mov %0, %%cr0"
                : "+r"(val));
}

void enable_memory_protection(void)
{
        force_write_cr0(read_cr0() | (WP_BIT));
}

void disable_memory_protection(void)
{
        force_write_cr0(read_cr0() & (~WP_BIT));
}
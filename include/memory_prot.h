#ifndef BSO_ANTROOTKIT_LKM_MEMORY_PROT_H
#define BSO_ANTROOTKIT_LKM_MEMORY_PROT_H

#include "check_wp_bit.h"
#include "utils.h"
#include <linux/kernel.h> // Types, macros, functions for the kernel
#include <linux/slab.h> // Allocate/free kernel memory + read_cr0()

static inline void force_write_cr0(unsigned long val)
{
	asm volatile("mov %0, %%cr0" : "+r"(val));
}

static inline void enable_memory_protection(void)
{
	force_write_cr0(read_cr0() | (WP_BIT));
}

static inline void disable_memory_protection(void)
{
	force_write_cr0(read_cr0() & (~WP_BIT));
}

#endif //BSO_ANTROOTKIT_LKM_MEMORY_PROT_H

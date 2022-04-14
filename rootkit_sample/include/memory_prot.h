#ifndef BSO_ROOTKIT_MEMORY_PROT_H
#define BSO_ROOTKIT_MEMORY_PROT_H

#include <linux/kernel.h>   // Types, macros, functions for the kernel
#include <linux/slab.h>     // Allocate/free kernel memory + read_cr0()

/*
 * Workaround for overwriting cr0 register (instead of using write_cr0()).
 */
inline void force_write_cr0(unsigned long val);

void enable_memory_protection(void);

void disable_memory_protection(void);

#endif //BSO_ROOTKIT_MEMORY_PROT_H



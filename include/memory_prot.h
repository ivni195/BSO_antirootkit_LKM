#ifndef BSO_ANTROOTKIT_LKM_MEMORY_PROT_H
#define BSO_ANTROOTKIT_LKM_MEMORY_PROT_H

#include <linux/kernel.h>   // Types, macros, functions for the kernel
#include <linux/slab.h>     // Allocate/free kernel memory + read_cr0()
#include "utils.h"

/*
 * Workaround for overwriting cr0 register (instead of using write_cr0()).
 */
inline void force_write_cr0(unsigned long val);

/*
 * Set the MP bit of the CR0 register.
 */
void enable_memory_protection(void);

/*
 * Clear the MP bit of the CR0 register
 */
void disable_memory_protection(void);

#endif //BSO_ANTROOTKIT_LKM_MEMORY_PROT_H

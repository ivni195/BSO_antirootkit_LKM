#ifndef BSO_ANTROOTKIT_LKM_MEMORY_PROT_H
#define BSO_ANTROOTKIT_LKM_MEMORY_PROT_H

#include "check_wp_bit.h"
#include "utils.h"
#include <linux/kernel.h>// Types, macros, functions for the kernel
#include <linux/slab.h>  // Allocate/free kernel memory + read_cr0()

/*
 * Workaround for overwriting cr0 register (instead of using write_cr0()).
 */
inline void force_write_cr0(unsigned long val);

/*
 * Set the WP bit of the CR0 register.
 */
void enable_memory_protection(void);

/*
 * Clear the WP bit of the CR0 register
 */
void disable_memory_protection(void);

#endif//BSO_ANTROOTKIT_LKM_MEMORY_PROT_H

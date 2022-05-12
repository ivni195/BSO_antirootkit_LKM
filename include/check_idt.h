#ifndef BSO_ANTIROOTKIT_LKM_CHECK_IDT_H
#define BSO_ANTIROOTKIT_LKM_CHECK_IDT_H

#include <asm/desc_defs.h>
#include <asm/desc.h>
#include "utils.h"
#include "memory_prot.h"

bool setup_int_check(void);
void compare_idt(void);

#endif //BSO_ANTIROOTKIT_LKM_CHECK_IDT_H

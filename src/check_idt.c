#include "check_idt.h"

static gate_desc idt_saved[IDT_ENTRIES];
static gate_desc *idt_real;

bool setup_int_check(void)
{
	struct desc_ptr idt_desc;
	store_idt(&idt_desc);

	if (idt_desc.size != (IDT_ENTRIES * sizeof(gate_desc)) - 1)
		return false;

	idt_real = (gate_desc *)idt_desc.address;
	memcpy(idt_saved, (const void *)idt_real, idt_desc.size);

	return true;
}

void compare_idt(void)
{
	int i;
	unsigned long real_addr, saved_addr;
	for (i = 0; i < IDT_ENTRIES; i++) {
		real_addr = gate_offset(&idt_real[i]);
		saved_addr = gate_offset(&idt_saved[i]);
		if (real_addr != saved_addr) {
			rk_warning("Found a IDT overwrite. Restoring...");
			disable_memory_protection();
			idt_real[i] = idt_saved[i];
			enable_memory_protection();
		}
	}
}

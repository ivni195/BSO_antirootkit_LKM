# About
This a simple antirootkit system created for a university course.
It was created and tested on Ubuntu 20.04 with kernel 5.13.0 (x86_64).

# Install
## Be careful!
This module is not 100% stable so **use a virtual machine**
to avoid any potential kernel panics or other nasty stuff.
## Linux headers
Install linux kernel headers.
### apt
`sudo apt install linux-headers-$(uname -r)`
### pacman
`sudo pacman -S linux-headers`
### yum
`sudo yum install kernel-devel`

## Build and load
In order to build 
1. Enter the `BSO_antirootkit_LKM` directory.
2. (Optional) Choose checks to be run by editing `include/config.h`.
3. Build with `make`.
4. Load the module with `make load`.
5. Unload the module with `make unload`.
6. Check output with `dmesg`.

# Kernel integrity checks
## Syscall hooks
`sys_call_table` is a kernel structure that stores addresses of syscalls.
Rootkits may try to overwrite the table's entries with malicious ones.
### kallsyms_lookup_name
First, we need to find the `sys_call_table` address.
To do so, we might use `kallsyms_lookup_name` function which takes a symbol's name
and returns its address. 
In newer kernel versions (> 5.7.0) this function is no longer exported. 
Thus, we need to use the following workaround that uses kernel probes 
```c
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

void setup_sys_call_check(void) {
//    Create kernel probe and set kp.symbol_name to the desired function
    struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
    };
//    Create a function pointer that will later store the desired address
    kallsyms_lookup_name_t kallsyms_lookup_name;
//    Register kprobe, so it searches for the symbol given by kp.symbol_name
    register_kprobe(&kp);
//    Retrieve address
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
//    Now we can unregister kprobe and return the pointer to sys_call_table
    unregister_kprobe(&kp);
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
}
```
### Disabling memory write protection
Now we have the `sys_call_table` address, but we still can't overwrite its entries,
because it's read-only. We read from the Intel manual 
> Write Protect (bit 16 of CR0) — When set, inhibits supervisor-level procedures from writing into read-
> only pages; when clear, allows supervisor-level procedures to write into read-only pages (...).

We need to clear the `WP` bit of `cr0` register. In modern kernels 
using the function `native_write_cr0` gives a permission error.
The kernel doesn't allow you to remove write protection.
Of course, we can bypass it by forcefully writing to `cr0` with
```c
inline void force_write_cr0(unsigned long val) {
    asm volatile(
    "mov %0, %%cr0"
    : "+r"(val)
    );
}
```
so that we can disable WP with
```c
#define WP_BIT 0x10000

void disable_memory_protection(void) {
    force_write_cr0(read_cr0() & (~WP_BIT));
}
```
### Hooking syscalls
Now we just create our own function and overwrite `sys_call_table` with it.
We also want to store somewhere the original function pointers, so we can call them from within
our evil function.

### Detection
#### Comparison
This module creates a copy of `sys_call_table` on init. If our module was loaded before the rootkit,
we can compare addresses present in the table with the saved ones. If an address doesn't match,
it means that there is a hook. Then we can want the user and restore the original address.

#### is_kernel_text
However, even if a rootkit was loaded first, we can still try to detect hooks.
We iterate over every `sys_call_table` entry
and call `is_kernel_text` which takes an address tells us whether it belongs to the 
core kernel text memory section.
Similarily to `kallsyms_lookup_name`, this function isn't available by traditional means,
so we also have to do some address lookup kung-fu and reimplement our own `local_is_kernel_text`.
This is the original implementation in `linux/kallsyms.h`
```c
static inline int is_kernel_text(unsigned long addr)
{
	if ((addr >= (unsigned long)_stext && addr <= (unsigned long)_etext) ||
	    arch_is_kernel_text(addr))
		return 1;
	return in_gate_area_no_mm(addr);
}
```
Symbols `_stext, _etext, in_gate_area_no_mm` are not globally accessible, but we can call 
`kallsyms_lookup_name` to find and save them in locally created pointers.
```c
typedef int (*in_gate_area_no_mm_t)(unsigned long addr);

char *local_stext, *local_etext;
in_gate_area_no_mm_t local_in_gate_area_no_mm;

local_stext = (char *) kallsyms_lookup_name("_stext");
local_etext = (char *) kallsyms_lookup_name("_etext");
local_in_gate_area_no_mm = (in_gate_area_no_mm_t) kallsyms_lookup_name("in_gate_area_no_mm");
```

Now we can reimplement the `is_kernel_text`
```c
static int local_is_kernel_text(unsigned long addr){
    if ((addr >= (unsigned long)local_stext && addr <= (unsigned long)local_etext) ||
        arch_is_kernel_text(addr))
        return 1;
    return local_in_gate_area_no_mm(addr);
}
```
Whenever `local_is_kernel_text` returns 0, we warn the user and try to recover the address.
TODO
check call stacks and try to recover original address

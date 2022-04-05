# About

This is a simple antirootkit system created for a university course. It was created and tested on Ubuntu 20.04 with
kernel 5.13.0 (x86_64).

# Install

## Be careful!

This module is not stable so **use a virtual machine**
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

`sys_call_table` is a kernel structure that stores addresses of syscalls. Rootkits may try to overwrite the table's
entries with malicious ones.

### kallsyms_lookup_name

First, we need to find the `sys_call_table` address. To do so, we might use `kallsyms_lookup_name` function which takes
a symbol's name and returns its address. In newer kernel versions (> 5.7.0) this function is no longer exported. Thus,
we need to use the following workaround that uses kernel probes

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

Now we have the `sys_call_table` address, but we still can't overwrite its entries, because it's located in read-only
memory. The Intel manual reads:
> Write Protect (bit 16 of CR0) — When set, inhibits supervisor-level procedures from writing into read-
> only pages; when clear, allows supervisor-level procedures to write into read-only pages (...).

We need to clear the `WP` bit of `cr0` register. In modern kernels using the function `native_write_cr0` gives a
permission error. The kernel doesn't allow you to remove write protection. Of course, we can bypass it by forcefully
writing to `cr0` with

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

Now we just create our own function and overwrite `sys_call_table` with it. We also want to store somewhere the original
function pointers, so we can call them from within our evil hook.

### Detection

#### Comparison

This module creates a copy of `sys_call_table` on init. If our module was loaded before the rootkit, we can compare
addresses from the table currently present in memory with the saved ones. If addresses don't match, there is a hook.
Then we can warn the user and restore the original address.

#### core_kernel_text

However, even if a rootkit was loaded first, we can still try to detect hooks. We iterate over every `sys_call_table`
entry and call `core_kernel_text` which takes an address and tells us whether it belongs to the core kernel text memory
section. Similarily to `kallsyms_lookup_name`, this function isn't available by traditional means, so we also have to do
some address lookup. Whenever `core_kernel_text` returns 0, we warn the user and try to recover the address.

#### Recovering original syscalls

We can, once again using `kallsyms_lookup_name`, search for original syscalls. For every `sys_call_table`
entry that isn't originated in the core kernel text area, we take its name and call `kallsyms_lookup_name`. We retrieve
the address and write it to `sys_call_table`.

## Checking for ftrace hooks

### How it works

The aforementioned approach isn't able to detect all types of hooks. One may also hook syscalls (or, in general,
important functions) using ftrace. To understand how ftrace hooks functions, we can look at the first couple of bytes of
a function. We can use this fragment of code

```c
static void get_func_assembly(char *ptr){
    char bytes[201];
    int i;

    memzero_explicit(bytes, 201);

    for(i = 0; i < 100; i++){
        sprintf(bytes, "%s%02hhX", bytes, ptr[i]);
    }
    printk("%s\n", bytes);
}
```

After we call it on the address of `__x64_sys_kill`, we get

```
0F1F4400005531D2BE010000004889E54155415453654C8B2425C0FB01004883
EC38488B5F684C8B6F704C89E765488B042528000000488945E031C048C745B8
0000000048C745C00000000048C745C80000000048C745D00000000048C745D8
00000000
```

Now we can use a tool like https://defuse.ca/online-x86-assembler.htm to disassemble it

```
0:  0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
5:  55                      push   rbp
6:  31 d2                   xor    edx,edx
8:  be 01 00 00 00          mov    esi,0x1
d:  48 89 e5                mov    rbp,rsp
10: 41 55                   push   r13
12: 41 54                   push   r12
14: 53                      push   rbx
/* ... */
```

The first 5 bytes is just a nop. We can do the same thing, but after the `__x64_sys_kill` function is hooked with ftrace

```
0:  e8 1b 02 0a 2a          call   0x2a0a0220
5:  55                      push   rbp
6:  31 d2                   xor    edx,edx
8:  be 01 00 00 00          mov    esi,0x1
d:  48 89 e5                mov    rbp,rsp
10: 41 55                   push   r13
12: 41 54                   push   r12
14: 53                      push   rbx
/* ... */
```

The first 5-byte nop instruction was replaced by a call to an ftrace callback. This is the reason those 5 bytes are
there. If ftrace wants to hook a function, it replaces them with its own `call` instruction.

#### Note on avoiding recursion

Notice that at some point we want to call the original function
(otherwise we will very likely break something or even more likely a lot of things). However, if we call the original
function from within the wrapper, the ftrace hook will trigger again, we will go to the wrapper, which will call the
original and so on... To avoid this, we can simply shift the original function pointer by 5 bytes (we basically jump
over the ftrace call and get to the actual function code). You can read more about hooking with ftrace (and how the code
used here works)
on https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2.

### Detecting ftrace hooks

Detection here is pretty straightforward. We define a set of funtions that we want to monitor, and we check if 5 intial
bytes of those functions are the `nop` intruction. If they are not, we replace them with `nop`, effectively removing a
hook.

#### Whitelisting other modules

A problem arises when we use some legit software that traces functions for whatever reason. Our module would detect
those hooks and remove them, affecting the software's functionality. To avoid this unwanted behavior, we can whitelist
certain modules. If we detect a hook that leads to a whitelisted module's callback, we ignore the hook. The only problem
is: How do we find the callback address by only looking at the address of the hooked function?

#### Recovering callback address

To do it, we have to dive into the ftrace source code. First, let's take a look at `lookup_rec`

```c
static struct dyn_ftrace *lookup_rec(unsigned long start, unsigned long end)
```

It takes an address range and searches for hooked functions. If it finds a hooked functions, it returns the address
of `struct dyn_ftrace rec`, which is the ftrace record descriptor
(some ftrace's internal structure). Once we have the `rec`, we can pass it to

```c
unsigned long ftrace_get_addr_curr(struct dyn_ftrace *rec)
```

which returns the address of the trampoline that is being called. So we have the trampoline address. Now we can take a
look at how trampolines are created.

```c
static unsigned long
create_trampoline(struct ftrace_ops *ops, unsigned int *caller_size)
{
    /*...*/
    if (ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
        start_offset = (unsigned long)ftrace_regs_caller;
        end_offset = (unsigned long)ftrace_regs_caller_end;
        op_offset = (unsigned long)ftrace_regs_caller_op_ptr;
        call_offset = (unsigned long)ftrace_regs_call;
        jmp_offset = (unsigned long)ftrace_regs_caller_jmp;
    } else {
        start_offset = (unsigned long)ftrace_caller;
        end_offset = (unsigned long)ftrace_caller_end;
        op_offset = (unsigned long)ftrace_caller_op_ptr;
        call_offset = (unsigned long)ftrace_call;
        jmp_offset = 0;
    }
    /*
     * The address of the ftrace_ops that is used for this trampoline
     * is stored at the end of the trampoline. This will be used to
     * load the third parameter for the callback. Basically, that
     * location at the end of the trampoline takes the place of
     * the global function_trace_op variable.
     */
    size = end_offset - start_offset;
    /*...*/
    ptr = (unsigned long *)(trampoline + size + RET_SIZE);
    *ptr = (unsigned long)ops;
    /*...*/
}
```

To make ftrace hook any useful for a rootkit, it needs `FTRACE_OPS_FL_SAVE_REGS` to be set. Only then does it have
access to the registers (`struct pt_regs` to be precise)
of the hooked function, so we can assume that the first branch of `if` is run. Also, we see that the pointer to
hook's `ops` is saved on the trampoline.

We have the trampoline address, and we know where (within the trampoline) is the pointer to `ops`. Using those two
things we can now recover the `ops` of the hook. Here's a piece of code that does exactly that

```c
lookup_rec_t lookup_rec_;
ftrace_get_addr_curr_t ftrace_get_addr_curr_;
unsigned long caller_size;

bool lookup_helpers(void){
//    Call this function only after find_kallsyms_lookup_name
    lookup_rec_ = (lookup_rec_t) kallsyms_lookup_name_("lookup_rec");
    ftrace_get_addr_curr_ = (ftrace_get_addr_curr_t) kallsyms_lookup_name_("ftrace_get_addr_curr");
    caller_size = kallsyms_lookup_name_("ftrace_regs_caller_end") - kallsyms_lookup_name_("ftrace_regs_caller");

    return  lookup_rec_ != NULL &&
            ftrace_get_addr_curr_ != NULL &&
            caller_size != 0;
}

// Returns address to hook's ftrace_ops or NULL if NOP.
struct ftrace_ops *get_ftrace_ops(void *tr_func){
    struct dyn_ftrace *rec;
    char nop[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};
    unsigned long tramp;
    struct ftrace_ops **ops;

    if(memcmp(tr_func, nop, MCOUNT_INSN_SIZE) == 0){
        return NULL;
    }

    rec = lookup_rec_((unsigned long) tr_func, (unsigned long) tr_func);
    if(rec == NULL){
        return NULL;
    }
    
    tramp = ftrace_get_addr_curr_(rec);
    if(tramp == 0){
        return NULL;
    }
    
    ops = (struct ftrace_ops **) (caller_size + 1 + tramp);
    return *ops;
}
```

Once we have `ops` of the hook we can just look at `ops->func`, which is the callback that we want. Now, we can use

```c
struct module *__module_address(unsigned long addr)
```

to find if the callback address belongs to a module. If it does and the module is not whitelisted,
(or we can't find the module, which means it's hidden itself) we remove the hook.

## Checking the WriteProtect bit of the cr0 register

This check is pretty straightforward. It was already mentioned that in order to modify the `sys_call_table`, we need to
clear `WP` bit of `cr0` register, which enables us to write to read-only memory in ring 0. We just make sure that the
bit is set, and if it's not, we set it back.

Note. If this module detects hooks in `sys_call_table`, it will temporarily disable memory protection in order to
restore overwritten entries, and then will enable the protection back.

## Checking the `entry_SYSCALL_64`

We read from the Intel manual
> SYSCALL invokes an OS system-call handler at privilege level 0.
> It does so by loading RIP from the IA32_LSTAR
> MSR (after saving the address of the instruction following SYSCALL into RCX).
> (The WRMSR instruction ensures
> that the IA32_LSTAR MSR always contain a canonical address.)

In Linux, `IA32_LSTAR MSR` stores the address of `entry_SYSCALL_64`, which is the entry point for 64-bit syscalls. A
rootkit may overwrite the address using the `wrmsrl` macro and intercept all syscalls. We do the same thing as in
the `sys_call_table` case. We read the `MSR LSTAR`, make sure that the address belongs to the core kernel text and store
it. Then, we compare it with the address that's present in the register.

## Checking the hidden modules

After a rootkit inserts itself into kernel, it will probably try to hide itself. Many rootkits only remove themselves
from the `proc` linked list. It can achieve it by doing

```c
list_del(&THIS_MODULE->list);
```

However, that's not everything. The information about inserted modules can be also found in kobjects. The rootkit can
remove itself from the `kobj` list by running

```c
list_del(&THIS_MODULE->mkobj.kobj.entry);
```

We can check if a rootkit removed itself from both lists by iterating them and making sure their content is the same.

### Memory scanning

The above approach is most likely sufficient to find simple rootkits, but is very easy to bypass. A rootkit utilizing
DKOM can in fact remove itself from all kernel structures, making it impossible to uncloak the rootkit using only the
kernel's API.

To solve this problem, we can scan the memory and search for data structures that look like `struct module`. Then we
check if the kernel is aware of this structure (for example check the procfs module linked list). If it isn't, it means
we found a hidden module.

#### Finding the signature

I spend a lot of time trying to figure our the right signature and the answer came out to be very simple (I'm sure
there's more a sofisticated solution, but mine works just fine). This is a fragment of `struct module` definition

```c

struct module {
    /*...*/
    /* Sysfs stuff. */
    struct module_kobject mkobj;
    struct module_attribute *modinfo_attrs;
    const char *version;
    const char *srcversion;
    struct kobject *holders_dir;
    /*...*/
}
```

It contains `struct module_kobject`. Let's look at this as well

```c
struct module_kobject {
	struct kobject kobj;
	struct module *mod; /* <--- this is what we're looking for */
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
} __randomize_layout;
```

Turns out `struct module` contains a pointer to itself. Moreover, after some testing I found that modifying this pointer
crashes the module. Maybe I missed something and there is a way to change it, but this looks rosy anyway.

#### Finding memory boundaries

Now we want to go through module memory area. Let's find the boundaries first. They are not globally accessible. I used
the `__module_address` function to extract them.

```c
struct module *__module_address(unsigned long addr)
{
	struct module *mod;

	if (addr < module_addr_min || addr > module_addr_max)
		return NULL;

	module_assert_mutex_or_preempt();

	mod = mod_find(addr);
	if (mod) {
		BUG_ON(!within_module(addr, mod));
		if (mod->state == MODULE_STATE_UNFORMED)
			mod = NULL;
	}
	return mod;
}
```

Both boundaries are accessed here. We can print a first couple of bytes of this function and disassemble them.

```
0:  0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
5:  55                      push   rbp
6:  48 39 3d 0b 3b ca 01    cmp    QWORD PTR [rip+0x1ca3b0b],rdi        # 0x1ca3b18
d:  48 89 e5                mov    rbp,rsp
10: 0f 87 a9 00 00 00       ja     0xbf
16: 48 39 3d 03 3b ca 01    cmp    QWORD PTR [rip+0x1ca3b03],rdi        # 0x1ca3b20
1d: 73 22                   jae    0x41
1f: e9 9b 00 00 00          jmp    0xbf
```

We see the ftrace nop once again and, more importantly, those two addresses:
`0x1ca3b18 0x1ca3b20`. Using some ugly type casting, we recover the values

```c
module_addr_min = *(unsigned long *) ((void *) module_addr_ + 0x1ca3b18);
module_addr_max = *(unsigned long *) ((void *) module_addr_ + 0x1ca3b20);
```

#### Putting it all together

Now we can just scan the memory from `module_addr_min` to `module_addr_max`, work_fn for the signature and reveal some
sneaky rootkits.

```c
while ((unsigned long) ptr < module_addr_max) {
    ptr_mod = (struct module *) ptr;

//    Make sure we're looking at valid addresses. Check the first and the last address of the potential module struct.
    if (kern_addr_valid_((unsigned long) ptr_mod) &&
        kern_addr_valid_((unsigned long) ptr_mod + sizeof(struct module))) {
//        Check the struct module signature. This looks way too simple to be good, but it works.
        if (ptr_mod == ptr_mod->mkobj.mod) {
//            We found a valid module - now let's check if it's in the module list
            if(lookup_module_by_name(ptr_mod->name) == NULL){
                rk_warning("Looks like the \"%s\" module is hidden (found by a memory scan).", ptr_mod->name);
            }
        }
    }
    ptr += 0x10;
}
```


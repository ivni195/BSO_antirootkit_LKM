#include "ftrace_utils.h"

/*
 * Ftrace whitelisting stuff.
 */

unsigned long caller_size;

bool lookup_helpers(void)
{
	// Call this function only after find_kallsyms_lookup_name
	caller_size = kallsyms_lookup_name_("ftrace_regs_caller_end") -
		      kallsyms_lookup_name_("ftrace_regs_caller");

	return caller_size != 0;
}

// Returns address to hook's ftrace_ops or NULL if NOP.
struct ftrace_ops *get_ftrace_ops(void *tr_func)
{
	unsigned char nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned long tramp, call_offset;
	struct ftrace_ops **ops;

	// Make sure it isn't a nop and starts with e8.
	if (memcmp(tr_func, nop, MCOUNT_INSN_SIZE) == 0 ||
	    *(unsigned char *)tr_func != 0xe8) {
		return NULL;
	}

	// e8 <4 bytes long relative address>
	call_offset = *(int *)(tr_func + 1);
	// address is calculated relative to the next intruction's address
	tramp = (unsigned long)(call_offset + tr_func + MCOUNT_INSN_SIZE);

	// There's ftrace_ops saved on a certain offset.
	ops = (struct ftrace_ops **)(caller_size + 1 + tramp);
	return *ops;
}

/*
 * Hooking mechanism;
 * Stolen from https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2.
 */

/*
 * Insert addresses by resolving function name.
 */
static int resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = kallsyms_lookup_name_(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

	// Jump over the ftrace call intruction.
	*((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;

	return 0;
}

void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
			     struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

//	to avoid recursive
	if (module_addr_(parent_ip) == THIS_MODULE){
		return;
	}

	// Go to the wrapper function
	regs->ip = (unsigned long)hook->function;
}

int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = (ftrace_func_t)fh_ftrace_thunk;
	hook->ops.flags =
		FTRACE_OPS_FL_SAVE_REGS | // Fill struct pt_regs *regs
		FTRACE_OPS_FL_IPMODIFY; // We will modify the intruction pointer

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);

		/* Don’t forget to turn off ftrace in case of an error. */
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

		return err;
	}

	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0 ; i < count ; i++)
	{
		err = fh_install_hook(&hooks[i]);
		if(err)
			goto error;
	}
	return 0;

error:
	while (i != 0)
	{
		fh_remove_hook(&hooks[--i]);
	}
	return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0 ; i < count ; i++)
		fh_remove_hook(&hooks[i]);
}

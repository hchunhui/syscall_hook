#ifndef SYSCALL_HOOK_H
#define SYSCALL_HOOK_H

struct frame {
	unsigned long ret_addr;
	unsigned long nr_ret;
	unsigned long args[6];
};

int syscall_hook(struct frame *f);

#endif /* SYSCALL_HOOK_H */

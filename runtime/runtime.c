#define _GNU_SOURCE
#include <link.h>
#include <stddef.h>
#include <sys/mman.h>
#include <syscall.h>
#include <sched.h>
#include <errno.h>
#include "syscall_hook.h"

static int __thread reent = 0;
static int wrapper(struct frame *f)
{
	if (reent)
		return 0;

	reent++;

	// for fork()/vfork()/clone():
	// don't allow the child process to run in the same memory
	// space, expect the TLS descriptor is properly set.
	switch (f->nr_ret) {
	case SYS_vfork:
		f->nr_ret = SYS_fork;
		break;
	case SYS_clone:
		if (f->args[0] & CLONE_VFORK) {
			f->args[0] &= ~CLONE_VM;
		} else if ((f->args[0] & CLONE_VM) &&
			   !(f->args[0] & CLONE_SETTLS)) {
			f->nr_ret = -EINVAL;
			return 1;
		}
		break;
	}

	int ret = syscall_hook(f);

	reent--;
	return ret;
}

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
	for (int j = 0; j < info->dlpi_phnum; j++) {
		int p_type = info->dlpi_phdr[j].p_type;
		unsigned long *signature = (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
		if (p_type == PT_LOAD && *signature == 0x4b4f4f48ff00aa55ul) {
			*(signature + 1) = (unsigned long)(&wrapper);
			mprotect(signature, info->dlpi_phdr[j].p_memsz, PROT_READ | PROT_EXEC);
		}
	}
	return 0;
}

static void __attribute__((constructor)) init() {
	reent++;
	dl_iterate_phdr(callback, NULL);
	reent--;
}

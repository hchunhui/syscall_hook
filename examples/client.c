#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <syscall.h>
#include <string.h>
#include "syscall_hook.h"

static int common(struct frame *f, char *file)
{
	fprintf(stderr, "open: %s\n", file);
	return 0;
}

int syscall_hook(struct frame *f)
{
	if (f->nr_ret == SYS_write) {
		f->nr_ret = write(f->args[0], (void *) f->args[1], f->args[2]);
		return 1;
	} else if (f->nr_ret == SYS_mprotect) {
		fprintf(stderr, "%d: mprotect (0x%lx, 0x%lx, 0x%lx)\n",
			getpid(), f->args[0], f->args[1], f->args[2]);
		if (f->args[2] & PROT_EXEC) {
			f->nr_ret = -ENOSYS;
			return 1;
		}
	} else if (f->nr_ret == SYS_fork || f->nr_ret == SYS_clone) {
		static int __thread fork_count = 0;
		fork_count++;
		fprintf(stderr, "%s: pid: %d, fork_count: %d\n", f->nr_ret == SYS_fork ? "fork" : "clone", getpid(), fork_count);
		if (fork_count > 100) {
			f->nr_ret = -EAGAIN;
			return 1;
		}
	} else if (f->nr_ret == SYS_openat) {
		return common(f, (void *) f->args[1]);
	} else if (f->nr_ret == SYS_open) {
		return common(f, (void *) f->args[0]);
	} else if (f->nr_ret == SYS_getcwd) {
		fprintf(stderr, "%d: nr: %d, (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
			getpid(), f->nr_ret, f->args[0], f->args[1], f->args[2], f->args[3], f->args[4], f->args[5]);
	}
	return 0;
}

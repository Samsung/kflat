/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_KFLAT_IOCTLS_H
#define _LINUX_KFLAT_IOCTLS_H

#ifdef __KERNEL__
#include <linux/types.h>

#else /* __USER__ */
#include <stdint.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#endif /* __KERNEL__ */

#define RECIPE_LIST_BUFF_SIZE 4096

/* IOCTL interface */
struct kflat_ioctl_enable {
	pid_t pid;
	char target_name[128];
	int debug_flag;
	int use_stop_machine;
	int skip_function_body;
	int run_recipe_now;
};

struct kflat_ioctl_disable {
	int invoked;
	size_t size;
	int error;
};

struct kflat_ioctl_tests {
	int debug_flag;
	int use_stop_machine;
	int skip_memcpy;
	char test_name[128];
};

struct kflat_ioctl_mem_map {
	void *buffer;
	size_t size;
};

#define KFLAT_PROC_ENABLE _IOW('k', 2, struct kflat_ioctl_enable)
#define KFLAT_PROC_DISABLE _IOR('k', 3, struct kflat_ioctl_disable)
#define KFLAT_TESTS _IOW('k', 4, struct kflat_ioctl_tests)
#define KFLAT_MEMORY_MAP _IOR('k', 5, struct kflat_ioctl_mem_map)
#define KFLAT_GET_LOADED_RECIPES _IOR('k', 6, char [RECIPE_LIST_BUFF_SIZE])

#define KFLAT_MMAP_FLATTEN 0
#define KFLAT_MMAP_KDUMP 1

#endif /* _LINUX_KFLAT_IOCTLS_H */

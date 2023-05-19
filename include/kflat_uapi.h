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


/* KFLAT header format */
#define KFLAT_IMG_MAGIC		0x4e455454414c46ULL	// 'FLATTEN\0'
#define KFLAT_IMG_VERSION	0x2

struct flatten_header {
	uint64_t magic;
	uint32_t version;

	uintptr_t last_load_addr;
	uintptr_t last_mem_addr;

	size_t image_size;
	size_t memory_size;
	size_t ptr_count;
	size_t fptr_count;
	size_t root_addr_count;
	size_t root_addr_extended_count;
	size_t root_addr_extended_size;
	size_t fptrmapsz;
	size_t mcount;
};


/* IOCTL interface */
struct kflat_ioctl_enable {
	pid_t pid;
	char target_name[128];
	int debug_flag;
	int use_stop_machine;
	int skip_function_body;
};

struct kflat_ioctl_disable {
	int invoked;
	size_t size;
	int error;
};

struct kflat_ioctl_tests {
	int debug_flag;
	int use_stop_machine;
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

#define KFLAT_MMAP_FLATTEN 0
#define KFLAT_MMAP_KDUMP 1

#endif /* _LINUX_KFLAT_IOCTLS_H */

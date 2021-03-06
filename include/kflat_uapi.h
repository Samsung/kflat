/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_KFLAT_IOCTLS_H
#define _LINUX_KFLAT_IOCTLS_H

#ifdef __KERNEL__
#include <linux/types.h>

#else
#include <stdint.h>
#include <stdlib.h>
#endif

struct kflat_ioctl_init {
    size_t  size;
	int 	debug_flag;
};

struct kflat_ioctl_enable {
    pid_t   pid;
    char    target_name[128];
};

struct kflat_ioctl_mem_map {
	void* buffer;
	size_t size;
};

enum kflat_test_flags {
    KFLAT_DEBUG_FLAG = 1,
    KFLAT_TEST_ITER,
};

enum kflat_test_codes {
	CIRCLE = 1,
	STRINGSET,
	POINTER,
	CURRENTTASK,
	SIMPLE,
	OVERLAPLIST,
	OVERLAPPTR,
	STRUCTARRAY,
	RPOINTER,
	CIRCLEARG,
	GLOBALCHECK,
	PADDING,
	GETOBJECTCHECK,
	LIST,
	LISTHEAD,
	HLIST,
	LLIST,
	HNULLSLIST,
	RBNODE,
};

#define KFLAT_TEST_TO_ARG(CODE, FLAG)       ((uint64_t) CODE << 2 | FLAG)
#define KFLAT_ARG_TO_FLAG(ARG)              (ARG & 0b11)
#define KFLAT_ARG_TO_CODE(ARG)              (ARG >> 2)


#define KFLAT_INIT					_IOW('k', 1, struct kflat_ioctl_init)
#define KFLAT_PROC_ENABLE			_IOW('k', 2, struct kflat_ioctl_enable)
#define KFLAT_PROC_DISABLE			_IO ('k', 3)
#define KFLAT_TESTS     			_IOW('k', 4, uint64_t)
#define KFLAT_MEMORY_MAP			_IOR('k', 5, struct kflat_ioctl_mem_map)

#define KFLAT_MMAP_FLATTEN			0
#define KFLAT_MMAP_KDUMP			1

#endif /* _LINUX_KFLAT_IOCTLS_H */

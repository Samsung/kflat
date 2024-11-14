/**
 * @file probing.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Interface for instrumenting Linux kernel with Kprobe subsystem
 *
 */

#ifndef _LINUX_PROBING_H
#define _LINUX_PROBING_H

#include <linux/mutex.h>
#include <linux/kprobes.h>

#include "kflat.h"

/*
 * MODULE CONFIGURATION
 */
#define PROBING_ENABLE_DEBUG 0

/*
 * Exported functions
 */
void probing_init(struct kflat* kflat);
int probing_arm(struct kflat* kflat, const char* symbol, pid_t callee);
void probing_disarm(struct kflat* kflat);
void* probing_get_kallsyms(void);

#endif

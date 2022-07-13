/*
 * Copyright 2022 Samsung R&D Poland
 *   Mobile Security Group
 *
 * Interface for instrumenting Linux kernel with Kprobe subsystem
 */

#include <linux/mutex.h>
#include <linux/kprobes.h>

#include "kflat.h"

/*
 * MODULE CONFIGURATION
 */
#define PROBING_ENABLE_DEBUG 1

/*
 * Exported functions
 */
int probing_arm(struct probe* probing, const char* symbol, pid_t callee);
void probing_disarm(struct probe* probing);

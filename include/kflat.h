/**
 * @file kflat.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Main Kernel Flattening (KFLAT) engine header file
 * 
 */
#ifndef _LINUX_KFLAT_H
#define _LINUX_KFLAT_H

#ifndef FLATTEN_KERNEL_BSP
#define FLATTEN_KERNEL_BSP
#endif

#include "kflat_uapi.h"
#include "kdump.h"
#include "flatten.h"
#include <linux/version.h>


/*******************************
 * LOGGING FMT WRAPPER
 *******************************/
#undef pr_fmt
#define pr_fmt(fmt) 		"kflat: " fmt


/*******************************
 * KFLAT SPECIFIC TYPES
 *******************************/
struct kflat;

#ifdef CONFIG_ARM64
struct probe_regs {
	union {
		uint64_t r[30];
		struct {
			// Procedure Call Standard for the ARMv8-A
			uint64_t arg1;			// X0
			uint64_t arg2;			// X1
			uint64_t arg3;			// X2
			uint64_t arg4;			// X3
			uint64_t arg5;			// X4
			uint64_t arg6;			// X5
			uint64_t arg7;			// X6
			uint64_t arg8;			// X7
			uint64_t _unused[8];		// X8..x15
			uint64_t kflat_ptr;		// X16 (stores pointer to KFLAT structure)
		} __packed;
	};
	uint64_t NZCV;
	uint64_t lr;
} __packed;

#elif CONFIG_X86_64
struct probe_regs {
	uint64_t EFLAGS;
	union {
		struct {
			uint64_t r[14];			// RAX .. R9
		}  __packed;
		struct {
			// SystemV AMD64 ABI
			uint64_t kflat_ptr;		// RAX (stores pointer to KFLAT structure)
			uint64_t _unused;		// RBX
			uint64_t arg4;			// RCX
			uint64_t arg3;      		// RDX
			uint64_t arg1;      		// RDI
			uint64_t arg2;      		// RSI
			uint64_t _unused2[1]; 		// RBP
			uint64_t arg5;			// R8
			uint64_t arg6;			// R9
		} __packed;
	};
} __packed;

#endif

struct probe {
	struct kprobe 		kprobe;
	struct mutex		lock;

	atomic_t		triggered;
	bool			is_armed;
	uint64_t 		return_ip;
	pid_t			callee_filter;
};

struct kflat_recipe {
	struct list_head 	list;
	struct module*      	owner;
	char* 			symbol;
	void 			(*handler)(struct kflat*, struct probe_regs*);
	void			(*pre_handler)(struct kflat*);
};

enum kflat_mode {
	KFLAT_MODE_DISABLED = 0,
	KFLAT_MODE_ENABLED
};

struct kflat {
	struct flat		flat;

	atomic_t		refcount;
	struct mutex		lock;
	enum kflat_mode		mode;

	pid_t			pid;
	struct probe		probing;
	struct kflat_recipe* 	recipe;
	struct kdump_memory_map mem_map;
	int 			use_stop_machine;
	int 			skip_function_body;
	int			debug_flag;
	wait_queue_head_t dump_ready_wq;
};

struct kflat_ksym {
	unsigned long address;
	size_t expected_size;
};

int kflat_recipe_get_all(char *buff, size_t bufsize);


/*******************************
 * EXPORTED FUNCTIONS
 *******************************/
int kflat_recipe_register(struct kflat_recipe* recipe);
int kflat_recipe_unregister(struct kflat_recipe* recipe);
struct kflat_recipe* kflat_recipe_get(char* name);
void kflat_recipe_put(struct kflat_recipe* recipe);

void kflat_get(struct kflat *kflat);
void kflat_put(struct kflat *kflat);

typedef unsigned long (*lookup_kallsyms_name_t)(const char* name);

// Before this patch https://patchwork.kernel.org/project/linux-trace-kernel/patch/20221230112729.351-2-thunder.leizhen@huawei.com/
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
typedef int (*module_kallsyms_on_each_symbol_t)(int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
typedef int (*kallsyms_on_each_symbol_t)(int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
// Before this patch https://patchwork.kernel.org/project/linux-trace-kernel/patch/20221230112729.351-4-thunder.leizhen@huawei.com/
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(6, 4, 0)
typedef int (*module_kallsyms_on_each_symbol_t)(const char *modname, int (*fn)(void *, const char *,  struct module *, unsigned long), void *data);
typedef int (*kallsyms_on_each_symbol_t)(int (*fn)(void *, const char *,  struct module *, unsigned long), void *data);
// Newest kernels
#else
typedef int (*module_kallsyms_on_each_symbol_t)(const char *modname, int (*fn)(void *, const char *, unsigned long), void *data);
typedef int (*kallsyms_on_each_symbol_t)(int (*fn)(void *, const char *, unsigned long), void *data);
#endif


extern lookup_kallsyms_name_t kflat_lookup_kallsyms_name;
extern module_kallsyms_on_each_symbol_t kflat_module_kallsyms_on_each_symbol;
extern kallsyms_on_each_symbol_t kflat_kallsyms_on_each_symbol;

int flatten_validate_inmem_size(char *mod_name, unsigned long address, size_t expected_size);

bool flatten_get_object(struct flat* flat, void* ptr, void** start, void** end);
void* flatten_global_address_by_name(const char* name);

#endif /* _LINUX_KFLAT_H */

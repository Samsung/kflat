/**
 * @file probing.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Interface for instrumenting Linux kernel with Kprobe subsystem
 * 
 */

#include "probing.h"
#include "kflat.h"

#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/version.h>

#ifndef __nocfi
#define __nocfi
#endif

/*******************************************************
 * DEBUG MACROS
 *******************************************************/
#if PROBING_ENABLE_DEBUG
#define PROBING_DEBUG(MSG, ...)      printk(KERN_DEBUG "kflat-probing[%d]: " MSG, current->pid, ##__VA_ARGS__)
#else
#define PROBING_DEBUG(MSG, ...)
#endif


/*******************************************************
 * EXTERNAL FUNCTIONS
 *******************************************************/
extern void raw_probing_delegate(void);


/*******************************************************
 * Probing internals
 *******************************************************/
static int probing_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct kflat* kflat;
    struct probe* probe;

    PROBING_DEBUG("kprobe entry");

    kflat = container_of(p, struct kflat, probing.kprobe);
    kflat_get(kflat);
    probe = &kflat->probing;

    // Apply PID filter
    if(probe->callee_filter > 0) {
        if(get_current()->pid != probe->callee_filter) {
            kflat_put(kflat);
            return 0;
        }
        PROBING_DEBUG("callee pid match - deploying delegate");
    } else
        PROBING_DEBUG("ignoring pid");

    if(atomic_cmpxchg(&probe->triggered, 0, 1) == 1) {
        PROBING_DEBUG("probe has been already triggered");
        kflat_put(kflat);
        return 0;
    }

#ifdef CONFIG_X86_64
    /* Kinda hacky. Kprobes in Linux kernel works by overwriting the code
     *  at specified address with one byte instruction INT3, generating #BP
     *  exception. The return address from this exception obviously points
     *  to the next instruction after INT3.
     * Our probing delegate unregisters kprobe to execute the original code
     *  of intercepted function. But to do this properly, it has to return to
     *  the first instruction of this function, which is return_address (regs->ip)
     *  minus the size of INT3 opcode (1byte).
     */
    kflat->probing.return_ip = regs->ip - 1;
    regs->ip = (u64) raw_probing_delegate;

    /* We're saving pointer to KFLAT structure associated with this Kprobe into 
     *  temporary register RAX, that is later also used in probing_x86.s to return
     *  to intercepted function code.
     */
    regs->ax = (unsigned long) kflat;
#endif

#ifdef CONFIG_ARM64
    /* In ARM64 architecture, return address from Breakpoint Instruction Exception
     *  points to the BRK instruction itself, i.e. to the beginning of intercepted
     *  function. Therefore, we don't need to do any magic trickery like in x86_64
     *  variant of this function.
     * 
     * For more details on this behaviour refer to ARMv8-A Architecture Reference 
     *  Manual (rev. G.b) section D2.8.3
     */
    kflat->probing.return_ip = regs->pc;
    regs->pc = (u64) raw_probing_delegate;

    /* Similarly to x86 variant, except in here we're using temporary register X16
     */
    regs->regs[16] = (u64) kflat;
#endif

    return 1;
}

static void probing_post_handler(struct kprobe* p, struct pt_regs* regs, unsigned long flags) {
    /*
     * Post handler is unused, but has to be declared to avoid `jmp optimization` used
     *  by kprobe subsystem. If kprobe decides to optimize probe, it wouldn't be possible
     *  to change the execution path in the way pre_handler does.
     */
    return;
}

/* Convert name of form "function+10" to symbol name (function) and offset (decimal) (10).
    Handles also plain "function", in which case offset is 0 */
static int symbol_to_name_and_offset(const char* symbol, char** pname, unsigned int* poffset) {
    int ret;
    char *offset_pos, *name;
    unsigned int offset = 0;

    name = kstrdup(symbol, GFP_KERNEL);
    if(name == NULL)
        return -ENOMEM;

    offset_pos = strchr(name, '+');
    if(offset_pos == NULL)
        goto exit;
    *offset_pos = '\0';
    
    ret = kstrtouint(offset_pos + 1, 10, &offset);
    if(ret) {
        kfree(name);
        return ret;
    }

exit:
    if(pname)
        *pname = name;
    if(poffset)
        *poffset = offset;
    return 0;
}

void probing_init(struct kflat* kflat) {
    struct probe* probing = &kflat->probing;
    memset(probing, 0, sizeof(*probing));
    mutex_init(&probing->lock);
}

int probing_arm(struct kflat* kflat, const char* symbol, pid_t callee) {
    int ret = 0;
    char* target_name;
    unsigned int target_offset;
    struct probe* probing = &kflat->probing;
    struct kprobe* kprobe = &kflat->probing.kprobe;

    ret = symbol_to_name_and_offset(symbol, &target_name, &target_offset);
    if(ret) {
        pr_err("failed to parse input symbol name");
        return ret;
    }

    mutex_lock(&probing->lock);
    if(probing->is_armed) {
        pr_err("failed to arm new kprobe - already armed");
        ret = -EAGAIN;
        kfree(target_name);
        goto exit;
    }
    probing->callee_filter = callee;

    memset(kprobe, 0, sizeof(*kprobe));
    kprobe->symbol_name = target_name;
    kprobe->offset = target_offset;
    kprobe->pre_handler = probing_pre_handler;
    kprobe->post_handler = probing_post_handler;

    ret = register_kprobe(kprobe);
    if(ret) {
        pr_err("failed to arm new kprobe - ret(%d)", ret);
        kfree(target_name);
        goto exit;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
    if(!(kprobe->flags & KPROBE_FLAG_ON_FUNC_ENTRY)) {
        pr_err("failed to arm new kprobe - symbol does not point to the start of function");
        unregister_kprobe(kprobe);
        kfree(target_name);
        goto exit;
    }
#endif

    atomic_set(&probing->triggered, 0);
    probing->is_armed = true;
    
exit:
    mutex_unlock(&probing->lock);
    return ret;
}
NOKPROBE_SYMBOL(probing_arm);

void probing_disarm(struct kflat* kflat) {
    struct probe* probing = &kflat->probing;
    mutex_lock(&probing->lock);

    if(!probing->is_armed)
        goto exit;
    
    atomic_set(&probing->triggered, 0);
    unregister_kprobe(&probing->kprobe);
    probing->is_armed = false;
    kfree(probing->kprobe.symbol_name);
    memset(&probing->kprobe, 0, sizeof(struct kprobe));

exit:
    mutex_unlock(&probing->lock);
    return;
}
NOKPROBE_SYMBOL(probing_disarm);


/*******************************************************
 * Cheating
 * 
 *  We really need an access to kallsyms_lookup_name for
 *  dumping global variables
 *******************************************************/
__nocfi void* probing_get_kallsyms(void) {
    int ret;
    void* result;
    struct kprobe kprobe;

    memset(&kprobe, 0, sizeof(kprobe));
    kprobe.symbol_name = "kallsyms_lookup_name";

    ret = register_kprobe(&kprobe);
    if(ret) {
        pr_err("failed to extract pointer to kallsyms_lookup_name - ret(%d)", ret);
        return NULL;
    }

    result = kprobe.addr;
    unregister_kprobe(&kprobe);

    if(result != NULL) {
        /* 
         * On some architectures (mainly x86_64) functions can be prefixed with
         *  control-flow integrity related instructions (like `endbr64`), which
         *  are being skipped in address returned by register_kprobe. Because of
         *  that, result could be set to something like kallsyms_lookup_name+0x4.
         * Normally that's not a problem, but with CFI enabled omitting endbr64
         *  instruction will trigger kernel fault.
         * To obtain the true starting address of kallsyms_lookup_name, we call
         *  the function pointer from kprobe with CFI disabled and store the result
         *  as real kallsyms_lookup_name address.
         */
        result = (void*) ((lookup_kallsyms_name_t)result)("kallsyms_lookup_name");
    }

    return result;
}

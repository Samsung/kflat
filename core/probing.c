/**
 * @file probing.c
 * @author Pawel Wieczorek (p.wieczorek@samsung.com)
 * @brief Interface for instrumenting Linux kernel with Kprobe subsystem
 * 
 */

#include "probing.h"
#include "kflat.h"

#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/slab.h>


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

void probing_init(struct kflat* kflat) {
    struct probe* probing = &kflat->probing;
    memset(probing, 0, sizeof(*probing));
    mutex_init(&probing->lock);
}

int probing_arm(struct kflat* kflat, const char* symbol, pid_t callee) {
    int ret = 0;
    struct probe* probing = &kflat->probing;
    struct kprobe* kprobe = &kflat->probing.kprobe;

    mutex_lock(&probing->lock);
    if(probing->is_armed) {
        pr_err("failed to arm new kprobe - already armed");
        ret = -EAGAIN;
        goto exit;
    }
    probing->callee_filter = callee;

    memset(kprobe, 0, sizeof(*kprobe));
    kprobe->symbol_name = symbol;
    kprobe->pre_handler = probing_pre_handler;
    kprobe->post_handler = probing_post_handler;

    ret = register_kprobe(kprobe);
    if(ret) {
        pr_err("failed to arm new kprobe - ret(%d)", ret);
        kfree(kprobe);
        goto exit;
    }

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
void* probing_get_kallsyms(void) {
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
    return result;
}

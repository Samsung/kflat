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
#ifdef PROBING_ENABLE_DEBUG
#define PROBING_DEBUG(MSG, ...)      printk(KERN_DEBUG "kflat-probing: " MSG, ##__VA_ARGS__)
#else
#define PROBING_DEBUG(MSG, ...)
#endif


/*******************************************************
 * EXTERNAL FUNCTIONS
 *******************************************************/
extern void raw_probing_delegate(void);
extern struct kflat* kflat_get_current(void);       // FIXME


/*******************************************************
 * Probing internals
 *******************************************************/
static int probing_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct kflat* kflat;

    PROBING_DEBUG("kprobe entry");

    kflat = kflat_get_current();
    if(kflat == NULL)
        return 0;

    PROBING_DEBUG("callee pid match - deploying delegate");

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

int probing_arm(struct probe* probing, const char* symbol, pid_t callee) {
    int ret;
    struct kprobe* kprobe;

    if(probing->is_armed) {
        pr_err("failed to arm new kprobe - already armed");
        return -EFAULT;
    }

    kprobe = kmalloc(sizeof(*kprobe), GFP_KERNEL);
    if(kprobe == NULL)
        return -ENOMEM;

    memset(kprobe, 0, sizeof(*kprobe));
    kprobe->symbol_name = symbol;
    kprobe->pre_handler = probing_pre_handler;
    kprobe->post_handler = probing_post_handler;

    ret = register_kprobe(kprobe);
    if(ret) {
        pr_err("failed to arm new kprobe - ret(%d)", ret);
        kfree(kprobe);
        return ret;
    }

    probing->kprobe = kprobe;
    probing->triggered = 0;
    probing->is_armed = 1;
    return 0;
}

void probing_disarm(struct probe* probing) {
    if(!probing->is_armed)
        return;
    
    probing->triggered = 0;
    unregister_kprobe(probing->kprobe);
    kfree(probing->kprobe);

    probing->is_armed = 0;
    probing->kprobe = NULL;
}


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

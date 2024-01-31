/**
 * @file kflat_uaccess.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Header for managing unpriviledged memory access from the supervisor execution context
 * 
 */

#ifndef KFLAT_UACCESS_H
#define KFLAT_UACCESS_H

#include <linux/uaccess.h>

#ifdef CONFIG_X86_64
static bool __used x86_test_addr_canonical(void *addr) {
    unsigned long upper = ((unsigned long) addr) >> (47);
    return upper == 0 || upper == 0x1ffff;
} 

static inline bool __used x86_is_kernel_addr(void *addr) {
    unsigned long upper = ((unsigned long) addr) >> (47);
    return upper == 0x1ffff;
}

static bool __used x86_read_ua(void) {
    unsigned long rflags;

    asm (
        "pushfq \n"
        "pop %0 \n"
        : "=r" (rflags)
        :
    );
    
    return (rflags >> 18) & 1;
}

#define arch_is_kernel_addr(__addr) x86_is_kernel_addr(__addr)
#define arch_read_ua() x86_read_ua()
#define arch_enable_ua() stac()
#define arch_disable_ua() clac()
#endif /* CONFIG_X86_64 */


#ifdef CONFIG_ARM64

static inline bool arm64_is_kernel_addr(void *addr) {
    unsigned long upper = ((unsigned long) addr) >> 63;
    return upper == 1;
}

/* ARM assembler doesn't understand MRS Xt, PAN for some reason, so we have to assemble 
 * the instruction ourselves.
 * 0xd5384260 == "MRS x0, PAN"
 */	
#define GET_PSTATE_PAN()	__emit_inst(0xd5384260)

static inline bool arm64_read_ua(void) {
    unsigned long a;
    asm(
        GET_PSTATE_PAN()
        "mov %0, X0" 
        : "=r" (a)
        :
        : "x0"
    );

    return !(a >> 22);
}

#define arch_is_kernel_addr(__addr) arm64_is_kernel_addr(__addr)
#define arch_read_ua() arm64_read_ua()
#define arch_enable_ua() uaccess_enable_privileged()
#define arch_disable_ua() uaccess_disable_privileged()
#endif /* CONFIG_ARM64 */

#endif /* KFLAT_UACCESS_H */
#include <linux/linkage.h>
#include <linux/init.h>
#include <linux/version.h>
#include <asm/nospec-branch.h>

/* Setup stack frame, dump current context and
 * jump to the C handler. After it finishes its
 * execution, restore context and jump back to the
 * original code
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 76)
ENTRY(raw_probing_delegate)
#else
SYM_CODE_START(raw_probing_delegate)
#endif
    /* Mark this code as a valid location for jump.
       Otherwise Control Flow Integrity (CFI)
       would crash the kernel  */
    endbr64;

    /* Dump current context */
    push %r15;
    push %r14;
    push %r13;
    push %r12;
    push %r11;
    push %r10;
    push %r9;
    push %r8;
    push %rbp;
    push %rsi;
    push %rdi;
    push %rdx;
    push %rcx;
    push %rbx;
    push %rax;
    pushfq;


    /* Jump to handler */
    mov     %rsp, %rdi;
    call    probing_delegate;
    /* %rax holds saved_ip address */


    /* Restore current context */
    popfq;
    pop %rbx;   /* Preserve the value of %rax register */
    pop %rbx;
    pop %rcx;
    pop %rdx;
    pop %rdi;
    pop %rsi;
    pop %rbp;
    pop %r8;
    pop %r9;
    pop %r10;
    pop %r11;
    pop %r12;
    pop %r13;
    pop %r14;
    pop %r15;

    /* If saved_ip is NULL, set return value (rax) to 0 
     *  and return to parent function
     */
    cmpq $0, %rax;
    jz  1f

    ANNOTATE_RETPOLINE_SAFE;
    jmp    *%rax;            /* Jump back to saved_ip */

1:
    mov $0, %rax;
    RET

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 76)
END(raw_probing_delegate)
#else
SYM_CODE_END(raw_probing_delegate)
#endif

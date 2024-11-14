#include <linux/linkage.h>
#include <linux/init.h>

#include <asm/assembler.h>

/* Setup stack frame, dump current context and
 * jump to the C handler. After it finishes its
 * execution, restore context and jump back to the
 * original code
 */
SYM_CODE_START(raw_probing_delegate)
    /* Mark this code as a valid location for jump
     *  Otherwise Branch Target Identification (BTI)
     *  would crash the kernel
     */
    hint    0x26;           /* BTI jc */

    /* Setup stack frame */
    sub    sp, sp, #16*16;

    /* Dump current context */
    stp	x0, x1, [sp, #16 * 0];
    stp	x2, x3, [sp, #16 * 1];
    stp	x4, x5, [sp, #16 * 2];
    stp	x6, x7, [sp, #16 * 3];
    stp	x8, x9, [sp, #16 * 4];
    stp	x10, x11, [sp, #16 * 5];
    stp	x12, x13, [sp, #16 * 6];
    stp	x14, x15, [sp, #16 * 7];
    stp	x16, x17, [sp, #16 * 8];
    stp	x18, x19, [sp, #16 * 9];
    stp	x20, x21, [sp, #16 * 10];
    stp	x22, x23, [sp, #16 * 11];
    stp	x24, x25, [sp, #16 * 12];
    stp	x26, x27, [sp, #16 * 13];
    stp	x28, x29, [sp, #16 * 14];
    mrs    x0, NZCV;
    stp    x0, lr, [sp, #16 * 15];


    /* Jump to handler */
    mov    x0, sp;
    bl     probing_delegate;

    /* x0 holds the return address */
    mov    x16, x0;


    /* Restore current context */
    ldp    x0, lr, [sp, #16 * 15];
    msr    NZCV, x0;
    ldp	x0, x1, [sp, #16 * 0];
    ldp	x2, x3, [sp, #16 * 1];
    ldp	x4, x5, [sp, #16 * 2];
    ldp	x6, x7, [sp, #16 * 3];
    ldp	x8, x9, [sp, #16 * 4];
    ldp	x10, x11, [sp, #16 * 5];
    ldp	x12, x13, [sp, #16 * 6];
    ldp	x14, x15, [sp, #16 * 7];
    ldp	x18, x17, [sp, #16 * 8];    /* Don't overwrite x16! */
    ldp	x18, x19, [sp, #16 * 9];
    ldp	x20, x21, [sp, #16 * 10];
    ldp	x22, x23, [sp, #16 * 11];
    ldp	x24, x25, [sp, #16 * 12];
    ldp	x26, x27, [sp, #16 * 13];
    ldp	x28, x29, [sp, #16 * 14];

    /* Restore stack frame */
    add    sp, sp, #16*16;

    /* Jump back to saved_ip. If saved_ip is NULL,
     *  set return value (x0) to 0 and return to
     *  parent function
     */
    cmp    x16, #0;
    b.eq   1f;
    br     x16;

1:
    mov    x0, #0;
    ret;
SYM_CODE_END(raw_probing_delegate)

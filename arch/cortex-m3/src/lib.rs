//! Shared implementations for ARM Cortex-M3 MCUs.

#![crate_name = "cortexm3"]
#![crate_type = "rlib"]
#![feature(llvm_asm, naked_functions)]
#![no_std]

pub mod mpu;

// Re-export the base generic cortex-m functions here as they are
// valid on cortex-m3.
pub use cortexm::support;

pub use cortexm::hard_fault_handler_m3plus as hard_fault_handler;
pub use cortexm::nvic;
pub use cortexm::print_cortexm_state as print_cortexm3_state;
pub use cortexm::scb;
pub use cortexm::syscall;
pub use cortexm::systick;

extern "C" {
    // _estack is not really a function, but it makes the types work
    // You should never actually invoke it!!
    fn _estack();
    static mut _sstack: u32;
    static mut _szero: u32;
    static mut _ezero: u32;
    static mut _etext: u32;
    static mut _srelocate: u32;
    static mut _erelocate: u32;
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn systick_handler() {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
pub unsafe extern "C" fn systick_handler() {
    llvm_asm!(
        "
    /* Mark that the systick handler was called meaning that the process */
    /* stopped executing because it has exceeded its timeslice. */
    ldr r0, =SYSTICK_EXPIRED
    mov r1, #1
    str r1, [r0, #0]

    /* Set thread mode to privileged */
    mov r0, #0
    msr CONTROL, r0
    /* CONTROL writes must be followed by ISB */
    /* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dai0321a/BIHFJCAC.html */
    isb

    movw LR, #0xFFF9
    movt LR, #0xFFFF"
    : : : : "volatile" );
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn generic_isr() {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
/// All ISRs are caught by this handler which disables the NVIC and switches to the kernel.
pub unsafe extern "C" fn generic_isr() {
    llvm_asm!(
        "
    /* Skip saving process state if not coming from user-space */
    cmp lr, #0xfffffffd
    bne _ggeneric_isr_no_stacking

    /* We need the most recent kernel's version of r1, which points */
    /* to the Process struct's stored registers field. The kernel's r1 */
    /* lives in the second word of the hardware stacked registers on MSP */
    mov r1, sp
    ldr r1, [r1, #4]
    stmia r1, {r4-r11}

    /* Set thread mode to privileged */
    mov r0, #0
    msr CONTROL, r0
    /* CONTROL writes must be followed by ISB */
    /* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dai0321a/BIHFJCAC.html */
    isb

    movw LR, #0xFFF9
    movt LR, #0xFFFF
  _ggeneric_isr_no_stacking:
    /* Find the ISR number by looking at the low byte of the IPSR registers */
    mrs r0, IPSR
    and r0, #0xff
    /* ISRs start at 16, so substract 16 to get zero-indexed */
    sub r0, #16

    /*
     * High level:
     *    NVIC.ICER[r0 / 32] = 1 << (r0 & 31)
     * */
    lsrs r2, r0, #5 /* r2 = r0 / 32 */

    /* r0 = 1 << (r0 & 31) */
    movs r3, #1        /* r3 = 1 */
    and r0, r0, #31    /* r0 = r0 & 31 */
    lsl r0, r3, r0     /* r0 = r3 << r0 */

    /* r3 = &NVIC.ICER */
    mov r3, #0xe180
    movt r3, #0xe000

    /* here:
     *
     *  `r2` is r0 / 32
     *  `r3` is &NVIC.ICER
     *  `r0` is 1 << (r0 & 31)
     *
     * So we just do:
     *
     *  `*(r3 + r2 * 4) = r0`
     *
     *  */
    str r0, [r3, r2, lsl #2]

    /* The pending bit in ISPR might be reset by hardware for pulse interrupts
     * at this point. So set it here again so the interrupt does not get lost
     * in service_pending_interrupts()
     * */
    /* r3 = &NVIC.ISPR */
    mov r3, #0xe200
    movt r3, #0xe000
    /* Set pending bit */
    str r0, [r3, r2, lsl #2]"
    : : : : "volatile" );
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn svc_handler() {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
pub unsafe extern "C" fn svc_handler() {
    llvm_asm!(
        "
    cmp lr, #0xfffffff9
    bne to_kernel

    /* Set thread mode to unprivileged */
    mov r0, #1
    msr CONTROL, r0
    /* CONTROL writes must be followed by ISB */
    /* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dai0321a/BIHFJCAC.html */
    isb

    movw lr, #0xfffd
    movt lr, #0xffff
    bx lr
  to_kernel:
    ldr r0, =SYSCALL_FIRED
    mov r1, #1
    str r1, [r0, #0]

    /* Set thread mode to privileged */
    mov r0, #0
    msr CONTROL, r0
    /* CONTROL writes must be followed by ISB */
    /* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dai0321a/BIHFJCAC.html */
    isb

    movw LR, #0xFFF9
    movt LR, #0xFFFF
    bx lr"
    : : : : "volatile" );
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn switch_to_user(
    _user_stack: *const u8,
    _process_regs: &mut [usize; 8],
) -> *const usize {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[no_mangle]
/// r0 is top of user stack, r1 is reference to `CortexMStoredState.regs`
pub unsafe extern "C" fn switch_to_user(
    mut user_stack: *const usize,
    process_regs: &mut [usize; 8],
) -> *const usize {
    llvm_asm!("
    /* Load bottom of stack into Process Stack Pointer */
    msr psp, $0

    /* Load non-hardware-stacked registers from Process stack */
    /* Ensure that $2 is stored in a callee saved register */
    ldmia $2, {r4-r11}

    /* SWITCH */
    svc 0xff /* It doesn't matter which SVC number we use here */

    /* Push non-hardware-stacked registers into Process struct's */
    /* regs field */
    stmia $2, {r4-r11}


    mrs $0, PSP /* PSP into r0 */"
    : "={r0}"(user_stack)
    : "{r0}"(user_stack), "{r1}"(process_regs)
    : "r4","r5","r6","r8","r9","r10","r11" : "volatile" );
    user_stack
}

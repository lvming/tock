//! Shared implementations for ARM Cortex-M4 MCUs.

#![crate_name = "cortexm4"]
#![crate_type = "rlib"]
#![feature(llvm_asm, naked_functions)]
#![no_std]

pub mod mpu;

// Re-export the base generic cortex-m functions here as they are
// valid on cortex-m4.
pub use cortexm::support;

pub use cortexm::hard_fault_handler_m3plus as hard_fault_handler;
pub use cortexm::nvic;
pub use cortexm::print_cortexm_state as print_cortexm4_state;
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

/// The `systick_handler` is called when the systick interrupt occurs, signaling
/// that an application executed for longer than its timeslice. If this is
/// called we want to return to the scheduler.
#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
pub unsafe extern "C" fn systick_handler() {
    llvm_asm!(
        "
    // Mark that the systick handler was called meaning that the process stopped
    // executing because it has exceeded its timeslice. This is a global
    // variable that the `UserspaceKernelBoundary` code uses to determine why
    // the application stopped executing.
    ldr r0, =SYSTICK_EXPIRED
    mov r1, #1
    str r1, [r0, #0]

    // Set thread mode to privileged to switch back to kernel mode.
    mov r0, #0
    msr CONTROL, r0
    /* CONTROL writes must be followed by ISB */
    /* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dai0321a/BIHFJCAC.html */
    isb

    movw LR, #0xFFF9
    movt LR, #0xFFFF

    // This will resume in the switch to user function where application state
    // is saved and the scheduler can choose what to do next.
    "
    : : : : "volatile" );
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn generic_isr() {
    unimplemented!()
}

/// All ISRs are caught by this handler. This must ensure the interrupt is
/// disabled (per Tock's interrupt model) and then as quickly as possible resume
/// the main thread (i.e. leave the interrupt context). The interrupt will be
/// marked as pending and handled when the scheduler checks if there are any
/// pending interrupts.
///
/// If the ISR is called while an app is running, this will switch control to
/// the kernel.
#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
pub unsafe extern "C" fn generic_isr() {
    llvm_asm!(
        "
    // Set thread mode to privileged to ensure we are executing as the kernel.
    // This may be redundant if the interrupt happened while the kernel code
    // was executing.
    mov r0, #0
    msr CONTROL, r0
    /* CONTROL writes must be followed by ISB */
    /* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dai0321a/BIHFJCAC.html */
    isb

    // This is a special address to return Thread mode with Main stack
    movw LR, #0xFFF9
    movt LR, #0xFFFF

    // Now need to disable the interrupt that fired in the NVIC to ensure it
    // does not trigger again before the scheduler has a chance to handle it. We
    // do this here in assembly for performance.
    //
    // The general idea is:
    // 1. Get the index of the interrupt that occurred.
    // 2. Set the disable bit for that interrupt in the NVIC.

    // Find the ISR number (`index`) by looking at the low byte of the IPSR
    // registers.
    mrs r0, IPSR       // r0 = Interrupt Program Status Register (IPSR)
    and r0, #0xff      // r0 = r0 & 0xFF
    sub r0, #16        // ISRs start at 16, so subtract 16 to get zero-indexed.

    // Now disable that interrupt in the NVIC.
    // High level:
    //    r0 = index
    //    NVIC.ICER[r0 / 32] = 1 << (r0 & 31)
    //
    lsrs r2, r0, #5    // r2 = r0 / 32

    // r0 = 1 << (r0 & 31)
    movs r3, #1        // r3 = 1
    and r0, r0, #31    // r0 = r0 & 31
    lsl r0, r3, r0     // r0 = r3 << r0

    // Load the ICER register address.
    mov r3, #0xe180    // r3 = &NVIC.ICER
    movt r3, #0xe000

    // Here:
    // - `r2` is index / 32
    // - `r3` is &NVIC.ICER
    // - `r0` is 1 << (index & 31)
    //
    // So we just do:
    //
    //  `*(r3 + r2 * 4) = r0`
    //
    str r0, [r3, r2, lsl #2]

    /* The pending bit in ISPR might be reset by hardware for pulse interrupts
     * at this point. So set it here again so the interrupt does not get lost
     * in service_pending_interrupts()
     * */
    /* r3 = &NVIC.ISPR */
    mov r3, #0xe200
    movt r3, #0xe000
    /* Set pending bit */
    str r0, [r3, r2, lsl #2]

    // Now we can return from the interrupt context and resume what we were
    // doing. If an app was executing we will switch to the kernel so it can
    // choose whether to service the interrupt.
    "
    : : : : "volatile" );
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn unhandled_interrupt() {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
pub unsafe extern "C" fn unhandled_interrupt() {
    let mut interrupt_number: u32;

    // IPSR[8:0] holds the currently active interrupt
    llvm_asm!(
    "mrs    r0, ipsr                    "
    : "={r0}"(interrupt_number)
    :
    : "r0"
    :
    );

    interrupt_number = interrupt_number & 0x1ff;

    panic!("Unhandled Interrupt. ISR {} is active.", interrupt_number);
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn svc_handler() {
    unimplemented!()
}

/// This is called after a `svc` instruction, both when switching to userspace
/// and when userspace makes a system call.
#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
pub unsafe extern "C" fn svc_handler() {
    llvm_asm!(
        "
    // First check to see which direction we are going in. If the link register
    // is something other than 0xfffffff9, then we are coming from an app which
    // has called a syscall.
    cmp lr, #0xfffffff9
    bne to_kernel

    // If we get here, then this is a context switch from the kernel to the
    // application. Set thread mode to unprivileged to run the application.
    mov r0, #1
    msr CONTROL, r0
    /* CONTROL writes must be followed by ISB */
    /* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dai0321a/BIHFJCAC.html */
    isb

    // This is a special address to return Thread mode with Process stack
    movw lr, #0xfffd
    movt lr, #0xffff
    // Switch to the app.
    bx lr

  to_kernel:
    // An application called a syscall. We mark this in the global variable
    // `SYSCALL_FIRED` which is stored in the syscall file.
    // `UserspaceKernelBoundary` will use this variable to decide why the app
    // stopped executing.
    ldr r0, =SYSCALL_FIRED
    mov r1, #1
    str r1, [r0, #0]

    // Set thread mode to privileged as we switch back to the kernel.
    mov r0, #0
    msr CONTROL, r0
    /* CONTROL writes must be followed by ISB */
    /* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dai0321a/BIHFJCAC.html */
    isb

    // This is a special address to return Thread mode with Main stack
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

/// Assembly function called from `UserspaceKernelBoundary` to switch to an
/// an application. This handles storing and restoring application state before
/// and after the switch.
#[cfg(all(target_arch = "arm", target_os = "none"))]
#[no_mangle]
pub unsafe extern "C" fn switch_to_user(
    mut user_stack: *const usize,
    process_regs: &mut [usize; 8],
) -> *const usize {
    llvm_asm!(
        "
    // The arguments passed in are:
    // - `r0` is the top of the user stack
    // - `r1` is a reference to `CortexMStoredState.regs`

    // Load bottom of stack into Process Stack Pointer.
    msr psp, $0

    // Load non-hardware-stacked registers from the process stored state. Ensure
    // that $2 is stored in a callee saved register.
    ldmia $2, {r4-r11}

    // SWITCH
    svc 0xff   // It doesn't matter which SVC number we use here as it has no
               // defined meaning for the Cortex-M syscall interface. Data being
               // returned from a syscall is transfered on the app's stack.

    // When execution returns here we have switched back to the kernel from the
    // application.

    // Push non-hardware-stacked registers into the saved state for the
    // application.
    stmia $2, {r4-r11}

    // Update the user stack pointer with the current value after the
    // application has executed.
    mrs $0, PSP   // r0 = PSP"
    : "={r0}"(user_stack)
    : "{r0}"(user_stack), "{r1}"(process_regs)
    : "r4","r5","r6","r8","r9","r10","r11" : "volatile" );
    user_stack
}

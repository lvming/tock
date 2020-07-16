//! Generic support for all Cortex-M platforms.

#![crate_name = "cortexm"]
#![crate_type = "rlib"]
#![feature(llvm_asm)]
#![no_std]

use core::fmt::Write;

pub mod nvic;
pub mod scb;
pub mod support;
pub mod syscall;
pub mod systick;

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[inline(never)]
unsafe fn kernel_hardfault_m3plus(faulting_stack: *mut u32) {
    let stacked_r0: u32 = *faulting_stack.offset(0);
    let stacked_r1: u32 = *faulting_stack.offset(1);
    let stacked_r2: u32 = *faulting_stack.offset(2);
    let stacked_r3: u32 = *faulting_stack.offset(3);
    let stacked_r12: u32 = *faulting_stack.offset(4);
    let stacked_lr: u32 = *faulting_stack.offset(5);
    let stacked_pc: u32 = *faulting_stack.offset(6);
    let stacked_xpsr: u32 = *faulting_stack.offset(7);

    let mode_str = "Kernel";

    let shcsr: u32 = core::ptr::read_volatile(0xE000ED24 as *const u32);
    let cfsr: u32 = core::ptr::read_volatile(0xE000ED28 as *const u32);
    let hfsr: u32 = core::ptr::read_volatile(0xE000ED2C as *const u32);
    let mmfar: u32 = core::ptr::read_volatile(0xE000ED34 as *const u32);
    let bfar: u32 = core::ptr::read_volatile(0xE000ED38 as *const u32);

    let iaccviol = (cfsr & 0x01) == 0x01;
    let daccviol = (cfsr & 0x02) == 0x02;
    let munstkerr = (cfsr & 0x08) == 0x08;
    let mstkerr = (cfsr & 0x10) == 0x10;
    let mlsperr = (cfsr & 0x20) == 0x20;
    let mmfarvalid = (cfsr & 0x80) == 0x80;

    let ibuserr = ((cfsr >> 8) & 0x01) == 0x01;
    let preciserr = ((cfsr >> 8) & 0x02) == 0x02;
    let impreciserr = ((cfsr >> 8) & 0x04) == 0x04;
    let unstkerr = ((cfsr >> 8) & 0x08) == 0x08;
    let stkerr = ((cfsr >> 8) & 0x10) == 0x10;
    let lsperr = ((cfsr >> 8) & 0x20) == 0x20;
    let bfarvalid = ((cfsr >> 8) & 0x80) == 0x80;

    let undefinstr = ((cfsr >> 16) & 0x01) == 0x01;
    let invstate = ((cfsr >> 16) & 0x02) == 0x02;
    let invpc = ((cfsr >> 16) & 0x04) == 0x04;
    let nocp = ((cfsr >> 16) & 0x08) == 0x08;
    let unaligned = ((cfsr >> 16) & 0x100) == 0x100;
    let divbysero = ((cfsr >> 16) & 0x200) == 0x200;

    let vecttbl = (hfsr & 0x02) == 0x02;
    let forced = (hfsr & 0x40000000) == 0x40000000;

    let ici_it = (((stacked_xpsr >> 25) & 0x3) << 6) | ((stacked_xpsr >> 10) & 0x3f);
    let thumb_bit = ((stacked_xpsr >> 24) & 0x1) == 1;
    let exception_number = (stacked_xpsr & 0x1ff) as usize;

    panic!(
        "{} HardFault.\r\n\
         \tKernel version {}\r\n\
         \tr0  0x{:x}\r\n\
         \tr1  0x{:x}\r\n\
         \tr2  0x{:x}\r\n\
         \tr3  0x{:x}\r\n\
         \tr12 0x{:x}\r\n\
         \tlr  0x{:x}\r\n\
         \tpc  0x{:x}\r\n\
         \tprs 0x{:x} [ N {} Z {} C {} V {} Q {} GE {}{}{}{} ; ICI.IT {} T {} ; Exc {}-{} ]\r\n\
         \tsp  0x{:x}\r\n\
         \ttop of stack     0x{:x}\r\n\
         \tbottom of stack  0x{:x}\r\n\
         \tSHCSR 0x{:x}\r\n\
         \tCFSR  0x{:x}\r\n\
         \tHSFR  0x{:x}\r\n\
         \tInstruction Access Violation:       {}\r\n\
         \tData Access Violation:              {}\r\n\
         \tMemory Management Unstacking Fault: {}\r\n\
         \tMemory Management Stacking Fault:   {}\r\n\
         \tMemory Management Lazy FP Fault:    {}\r\n\
         \tInstruction Bus Error:              {}\r\n\
         \tPrecise Data Bus Error:             {}\r\n\
         \tImprecise Data Bus Error:           {}\r\n\
         \tBus Unstacking Fault:               {}\r\n\
         \tBus Stacking Fault:                 {}\r\n\
         \tBus Lazy FP Fault:                  {}\r\n\
         \tUndefined Instruction Usage Fault:  {}\r\n\
         \tInvalid State Usage Fault:          {}\r\n\
         \tInvalid PC Load Usage Fault:        {}\r\n\
         \tNo Coprocessor Usage Fault:         {}\r\n\
         \tUnaligned Access Usage Fault:       {}\r\n\
         \tDivide By Zero:                     {}\r\n\
         \tBus Fault on Vector Table Read:     {}\r\n\
         \tForced Hard Fault:                  {}\r\n\
         \tFaulting Memory Address: (valid: {}) {:#010X}\r\n\
         \tBus Fault Address:       (valid: {}) {:#010X}\r\n\
         ",
        mode_str,
        option_env!("TOCK_KERNEL_VERSION").unwrap_or("unknown"),
        stacked_r0,
        stacked_r1,
        stacked_r2,
        stacked_r3,
        stacked_r12,
        stacked_lr,
        stacked_pc,
        stacked_xpsr,
        (stacked_xpsr >> 31) & 0x1,
        (stacked_xpsr >> 30) & 0x1,
        (stacked_xpsr >> 29) & 0x1,
        (stacked_xpsr >> 28) & 0x1,
        (stacked_xpsr >> 27) & 0x1,
        (stacked_xpsr >> 19) & 0x1,
        (stacked_xpsr >> 18) & 0x1,
        (stacked_xpsr >> 17) & 0x1,
        (stacked_xpsr >> 16) & 0x1,
        ici_it,
        thumb_bit,
        exception_number,
        ipsr_isr_number_to_str(exception_number),
        faulting_stack as u32,
        (_estack as *const ()) as u32,
        (&_sstack as *const u32) as u32,
        shcsr,
        cfsr,
        hfsr,
        iaccviol,
        daccviol,
        munstkerr,
        mstkerr,
        mlsperr,
        ibuserr,
        preciserr,
        impreciserr,
        unstkerr,
        stkerr,
        lsperr,
        undefinstr,
        invstate,
        invpc,
        nocp,
        unaligned,
        divbysero,
        vecttbl,
        forced,
        mmfarvalid,
        mmfar,
        bfarvalid,
        bfar
    );
}

// Mock implementation for tests on Travis-CI.
#[cfg(not(any(target_arch = "arm", target_os = "none")))]
pub unsafe extern "C" fn hard_fault_handler_m3plus() {
    unimplemented!()
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
#[naked]
pub unsafe extern "C" fn hard_fault_handler_m3plus() {
    let faulting_stack: *mut u32;
    let kernel_stack: bool;

    // First need to determine if this a kernel fault or a userspace fault.
    llvm_asm!(
    "
    mov    r1, 0     /* r1 = 0 */
    tst    lr, #4    /* bitwise AND link register to 0b100 */
    itte   eq        /* if lr==4, run next two instructions, else, run 3rd instruction. */
    mrseq  r0, msp   /* r0 = kernel stack pointer */
    addeq  r1, 1     /* r1 = 1, kernel was executing */
    mrsne  r0, psp   /* r0 = userland stack pointer */"
    : "={r0}"(faulting_stack), "={r1}"(kernel_stack)
    :
    : "r0", "r1"
    : "volatile" );

    if kernel_stack {
        // Need to determine if we had a stack overflow before we push anything
        // on to the stack. We check this by looking at the BusFault Status
        // Register's (BFSR) `LSPERR` and `STKERR` bits to see if the hardware
        // had any trouble stacking important registers to the stack during the
        // fault. If so, then we cannot use this stack while handling this fault
        // or we will trigger another fault.
        let stack_overflow: bool;
        llvm_asm!(
        "
        ldr   r2, =0xE000ED29  /* SCB BFSR register address */
        ldrb  r2, [r2]         /* r2 = BFSR */
        tst   r2, #0x30        /* r2 = BFSR & 0b00110000; LSPERR & STKERR bits */
        ite   ne               /* check if the result of that bitwise AND was not 0 */
        movne r3, #1           /* BFSR & 0b00110000 != 0; r3 = 1 */
        moveq r3, #0           /* BFSR & 0b00110000 == 0; r3 = 0 */"
        : "={r3}"(stack_overflow)
        :
        : "r3"
        : "volatile" );

        if stack_overflow {
            // The hardware couldn't use the stack, so we have no saved data and
            // we cannot use the kernel stack as is. We just want to report that
            // the kernel's stack overflowed, since that is essential for
            // debugging.
            //
            // To make room for a panic!() handler stack, we just re-use the
            // kernel's original stack. This should in theory leave the bottom
            // of the stack where the problem occurred untouched should one want
            // to further debug.
            llvm_asm!(
            "
            mov sp, r0   /* Set the stack pointer to _estack */"
            :
            : "{r0}"((_estack as *const ()) as u32)
            : "volatile" );

            // Panic to show the correct error.
            panic!("kernel stack overflow");
        } else {
            // Show the normal kernel hardfault message.
            kernel_hardfault_m3plus(faulting_stack);
        }
    } else {
        // Hard fault occurred in an app, not the kernel. The app should be
        // marked as in an error state and handled by the kernel.
        llvm_asm!(
        "
        /* Read the relevant SCB registers. */
        ldr r0, =SCB_REGISTERS  /* Global variable address */
        ldr r1, =0xE000ED14     /* SCB CCR register address */
        ldr r2, [r1, #0]        /* CCR */
        str r2, [r0, #0]
        ldr r2, [r1, #20]       /* CFSR */
        str r2, [r0, #4]
        ldr r2, [r1, #24]       /* HFSR */
        str r2, [r0, #8]
        ldr r2, [r1, #32]       /* MMFAR */
        str r2, [r0, #12]
        ldr r2, [r1, #36]       /* BFAR */
        str r2, [r0, #16]

        ldr r0, =APP_HARD_FAULT /* Global variable address */
        mov r1, #1              /* r1 = 1 */
        str r1, [r0, #0]        /* APP_HARD_FAULT = 1 */

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
}

pub unsafe fn print_cortexm_state(writer: &mut dyn Write) {
    let _ccr = syscall::SCB_REGISTERS[0];
    let cfsr = syscall::SCB_REGISTERS[1];
    let hfsr = syscall::SCB_REGISTERS[2];
    let mmfar = syscall::SCB_REGISTERS[3];
    let bfar = syscall::SCB_REGISTERS[4];

    let iaccviol = (cfsr & 0x01) == 0x01;
    let daccviol = (cfsr & 0x02) == 0x02;
    let munstkerr = (cfsr & 0x08) == 0x08;
    let mstkerr = (cfsr & 0x10) == 0x10;
    let mlsperr = (cfsr & 0x20) == 0x20;
    let mmfarvalid = (cfsr & 0x80) == 0x80;

    let ibuserr = ((cfsr >> 8) & 0x01) == 0x01;
    let preciserr = ((cfsr >> 8) & 0x02) == 0x02;
    let impreciserr = ((cfsr >> 8) & 0x04) == 0x04;
    let unstkerr = ((cfsr >> 8) & 0x08) == 0x08;
    let stkerr = ((cfsr >> 8) & 0x10) == 0x10;
    let lsperr = ((cfsr >> 8) & 0x20) == 0x20;
    let bfarvalid = ((cfsr >> 8) & 0x80) == 0x80;

    let undefinstr = ((cfsr >> 16) & 0x01) == 0x01;
    let invstate = ((cfsr >> 16) & 0x02) == 0x02;
    let invpc = ((cfsr >> 16) & 0x04) == 0x04;
    let nocp = ((cfsr >> 16) & 0x08) == 0x08;
    let unaligned = ((cfsr >> 16) & 0x100) == 0x100;
    let divbyzero = ((cfsr >> 16) & 0x200) == 0x200;

    let vecttbl = (hfsr & 0x02) == 0x02;
    let forced = (hfsr & 0x40000000) == 0x40000000;

    let _ = writer.write_fmt(format_args!("\r\n---| Fault Status |---\r\n"));

    if iaccviol {
        let _ = writer.write_fmt(format_args!(
            "Instruction Access Violation:       {}\r\n",
            iaccviol
        ));
    }
    if daccviol {
        let _ = writer.write_fmt(format_args!(
            "Data Access Violation:              {}\r\n",
            daccviol
        ));
    }
    if munstkerr {
        let _ = writer.write_fmt(format_args!(
            "Memory Management Unstacking Fault: {}\r\n",
            munstkerr
        ));
    }
    if mstkerr {
        let _ = writer.write_fmt(format_args!(
            "Memory Management Stacking Fault:   {}\r\n",
            mstkerr
        ));
    }
    if mlsperr {
        let _ = writer.write_fmt(format_args!(
            "Memory Management Lazy FP Fault:    {}\r\n",
            mlsperr
        ));
    }

    if ibuserr {
        let _ = writer.write_fmt(format_args!(
            "Instruction Bus Error:              {}\r\n",
            ibuserr
        ));
    }
    if preciserr {
        let _ = writer.write_fmt(format_args!(
            "Precise Data Bus Error:             {}\r\n",
            preciserr
        ));
    }
    if impreciserr {
        let _ = writer.write_fmt(format_args!(
            "Imprecise Data Bus Error:           {}\r\n",
            impreciserr
        ));
    }
    if unstkerr {
        let _ = writer.write_fmt(format_args!(
            "Bus Unstacking Fault:               {}\r\n",
            unstkerr
        ));
    }
    if stkerr {
        let _ = writer.write_fmt(format_args!(
            "Bus Stacking Fault:                 {}\r\n",
            stkerr
        ));
    }
    if lsperr {
        let _ = writer.write_fmt(format_args!(
            "Bus Lazy FP Fault:                  {}\r\n",
            lsperr
        ));
    }
    if undefinstr {
        let _ = writer.write_fmt(format_args!(
            "Undefined Instruction Usage Fault:  {}\r\n",
            undefinstr
        ));
    }
    if invstate {
        let _ = writer.write_fmt(format_args!(
            "Invalid State Usage Fault:          {}\r\n",
            invstate
        ));
    }
    if invpc {
        let _ = writer.write_fmt(format_args!(
            "Invalid PC Load Usage Fault:        {}\r\n",
            invpc
        ));
    }
    if nocp {
        let _ = writer.write_fmt(format_args!(
            "No Coprocessor Usage Fault:         {}\r\n",
            nocp
        ));
    }
    if unaligned {
        let _ = writer.write_fmt(format_args!(
            "Unaligned Access Usage Fault:       {}\r\n",
            unaligned
        ));
    }
    if divbyzero {
        let _ = writer.write_fmt(format_args!(
            "Divide By Zero:                     {}\r\n",
            divbyzero
        ));
    }

    if vecttbl {
        let _ = writer.write_fmt(format_args!(
            "Bus Fault on Vector Table Read:     {}\r\n",
            vecttbl
        ));
    }
    if forced {
        let _ = writer.write_fmt(format_args!(
            "Forced Hard Fault:                  {}\r\n",
            forced
        ));
    }

    if mmfarvalid {
        let _ = writer.write_fmt(format_args!(
            "Faulting Memory Address:            {:#010X}\r\n",
            mmfar
        ));
    }
    if bfarvalid {
        let _ = writer.write_fmt(format_args!(
            "Bus Fault Address:                  {:#010X}\r\n",
            bfar
        ));
    }

    if cfsr == 0 && hfsr == 0 {
        let _ = writer.write_fmt(format_args!("No faults detected.\r\n"));
    } else {
        let _ = writer.write_fmt(format_args!(
            "Fault Status Register (CFSR):       {:#010X}\r\n",
            cfsr
        ));
        let _ = writer.write_fmt(format_args!(
            "Hard Fault Status Register (HFSR):  {:#010X}\r\n",
            hfsr
        ));
    }
}

// Table 2.5
// http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0553a/CHDBIBGJ.html
pub fn ipsr_isr_number_to_str(isr_number: usize) -> &'static str {
    match isr_number {
        0 => "Thread Mode",
        1 => "Reserved",
        2 => "NMI",
        3 => "HardFault",
        4 => "MemManage",
        5 => "BusFault",
        6 => "UsageFault",
        7..=10 => "Reserved",
        11 => "SVCall",
        12 => "Reserved for Debug",
        13 => "Reserved",
        14 => "PendSV",
        15 => "SysTick",
        16..=255 => "IRQn",
        _ => "(Unknown! Illegal value?)",
    }
}

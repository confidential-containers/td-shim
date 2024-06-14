// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub use td_exception::interrupt::InterruptNoErrorStack;
pub use td_exception::{preserved_pop, preserved_push, scratch_pop, scratch_push};

// MSR registers
pub const MSR_LVTT: u32 = 0x832;
pub const MSR_INITIAL_COUNT: u32 = 0x838;
pub const MSR_TSC_DEADLINE: u32 = 0x6E0;
pub const MSR_DCR: u32 = 0x83e;

// APIC registers
pub const LOCAL_APIC_LVTT: u32 = 0xfee0_0320;
pub const INITIAL_COUNT: u32 = 0xfee0_0380;
pub const DIVIDE_CONFIGURATION_REGISTER: u32 = 0xfee0_03e0;

pub fn enable_apic_interrupt() {
    // Enable the local APIC by setting bit 8 of the APIC spurious vector region (SVR)
    // Ref: Intel SDM Vol3. 8.4.4.1
    // In x2APIC mode, SVR is mapped to MSR address 0x80f.
    // Since SVR(SIVR) is not virtualized, before we implement the handling in #VE of MSRRD/WR,
    // use tdvmcall instead direct read/write operation.
    let svr = tdx_tdcall::tdx::tdvmcall_rdmsr(0x80f).expect("fail to perform RDMSR operation\n");
    tdx_tdcall::tdx::tdvmcall_wrmsr(0x80f, svr | (0x1 << 8))
        .expect("fail to perform WRMSR operation\n");
}

pub fn enable_and_hlt() {
    #[cfg(feature = "tdx")]
    tdx_tdcall::tdx::tdvmcall_sti_halt();
    #[cfg(not(feature = "tdx"))]
    x86_64::instructions::interrupts::enable_and_hlt()
}

pub fn disable() {
    x86_64::instructions::interrupts::disable()
}

pub fn one_shot_tsc_deadline_mode(period: u64) -> Option<u64> {
    unsafe { x86::msr::wrmsr(MSR_TSC_DEADLINE, 0) }

    let tsc = unsafe { x86::time::rdtsc() };

    // Setup TSC Deadline Mode
    unsafe {
        x86::msr::wrmsr(MSR_TSC_DEADLINE, tsc.checked_add(period)?);
    }

    Some(period)
}

pub fn one_shot_tsc_deadline_mode_reset() {
    unsafe { x86::msr::wrmsr(MSR_TSC_DEADLINE, 0) }
}

#[macro_export]
macro_rules! interrupt_handler_template {
    ($name:ident, $stack: ident, $func:block) => {
        #[naked]
        #[no_mangle]
        /// # Safety
        ///
        /// Interrupt handler will handle the register reserve and restore
        pub unsafe extern fn $name () {
            #[inline(never)]
            /// # Safety
            ///
            /// Interrupt handler will handle the register reserve and restore
            unsafe extern "win64" fn inner($stack: &mut $crate::arch::apic::InterruptNoErrorStack) {
                $func
            }

            // Push scratch registers
            core::arch::asm!( concat!(
                $crate::arch::apic::scratch_push!(),
                $crate::arch::apic::preserved_push!(),
                "
                mov rcx, rsp
                call {inner}
                ",
                $crate::eoi!(),
                $crate::arch::apic::preserved_pop!(),
                $crate::arch::apic::scratch_pop!(),
                "
                iretq
                "
                ),
                inner = sym inner,
                options(noreturn),
            )
        }
    };
}

#[macro_export]
macro_rules! eoi {
    // Write the end-of-interrupt (EOI) register (0x80B) at the end of the handler
    // routine, sometime before the IRET instruction
    () => {
        "
        mov rcx, 0x80B
        mov edx, 0
        mov eax, 0
        wrmsr
    "
    };
}

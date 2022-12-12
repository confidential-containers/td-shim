// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::arch::asm;
#[cfg(feature = "tdx")]
use tdx_tdcall::tdx;

// the order is aligned with scratch_push!() and scratch_pop!()
#[repr(C, packed)]
pub struct ScratchRegisters {
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rsi: usize,
    pub rdi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rax: usize,
}

impl ScratchRegisters {
    pub fn dump(&self) {
        log::info!("RAX:   {:>016X}\n", { self.rax });
        log::info!("RCX:   {:>016X}\n", { self.rcx });
        log::info!("RDX:   {:>016X}\n", { self.rdx });
        log::info!("RDI:   {:>016X}\n", { self.rdi });
        log::info!("RSI:   {:>016X}\n", { self.rsi });
        log::info!("R8:    {:>016X}\n", { self.r8 });
        log::info!("R9:    {:>016X}\n", { self.r9 });
        log::info!("R10:   {:>016X}\n", { self.r10 });
        log::info!("R11:   {:>016X}\n", { self.r11 });
    }
}

#[macro_export]
macro_rules! scratch_push {
    () => {
        "
        push rax
        push rcx
        push rdx
        push rdi
        push rsi
        push r8
        push r9
        push r10
        push r11
    "
    };
}

#[macro_export]
macro_rules! scratch_pop {
    () => {
        "
        pop r11
        pop r10
        pop r9
        pop r8
        pop rsi
        pop rdi
        pop rdx
        pop rcx
        pop rax
    "
    };
}

#[repr(C, packed)]
pub struct PreservedRegisters {
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub rbp: usize,
    pub rbx: usize,
}

impl PreservedRegisters {
    pub fn dump(&self) {
        log::info!("RBX:   {:>016X}\n", { self.rbx });
        log::info!("RBP:   {:>016X}\n", { self.rbp });
        log::info!("R12:   {:>016X}\n", { self.r12 });
        log::info!("R13:   {:>016X}\n", { self.r13 });
        log::info!("R14:   {:>016X}\n", { self.r14 });
        log::info!("R15:   {:>016X}\n", { self.r15 });
    }
}

#[macro_export]
macro_rules! preserved_push {
    () => {
        "
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
    "
    };
}

#[macro_export]
macro_rules! preserved_pop {
    () => {
        "
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
    "
    };
}

#[repr(packed)]
pub struct IretRegisters {
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
}

impl IretRegisters {
    fn dump(&self) {
        log::info!("RFLAG: {:>016X}\n", { self.rflags });
        log::info!("CS:    {:>016X}\n", { self.cs });
        log::info!("RIP:   {:>016X}\n", { self.rip });
    }
}

#[repr(packed)]
pub struct InterruptNoErrorStack {
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    pub iret: IretRegisters,
}

impl InterruptNoErrorStack {
    pub fn dump(&self) {
        self.iret.dump();
        self.scratch.dump();
        self.preserved.dump();
    }
}

#[repr(packed)]
pub struct InterruptErrorStack {
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    pub code: usize,
    pub iret: IretRegisters,
}

impl InterruptErrorStack {
    pub fn dump(&self) {
        self.iret.dump();
        log::info!("CODE:  {:>016X}\n", { self.code });
        self.scratch.dump();
        self.preserved.dump();
    }
}

#[macro_export]
macro_rules! interrupt_common {
    ($name:ident, $stack: ident, $stack_type:ty, $func:block, $asm_epilogue:literal) => {
        #[naked]
        #[no_mangle]
        pub unsafe extern fn $name () {
            #[inline(never)]
            unsafe extern "win64" fn inner($stack: &mut $stack_type) {
                $func
            }

            // Push scratch registers
            asm!( concat!(
                scratch_push!(),
                preserved_push!(),
                "
                mov rcx, rsp
                call {inner}
                ",
                preserved_pop!(),
                scratch_pop!(),
                $asm_epilogue
                ),
                inner = sym inner,
                options(noreturn),
            )
        }
    };
}

#[macro_export]
macro_rules! interrupt_no_error {
    ($name:ident, $stack: ident, $func:block) => {
        interrupt_common!(
            $name,
            $stack,
            InterruptNoErrorStack,
            $func,
            "
            iretq
            "
        );
    };
}

#[macro_export]
macro_rules! interrupt_error {
    ($name:ident, $stack: ident, $func:block) => {
        interrupt_common!(
            $name,
            $stack,
            InterruptErrorStack,
            $func,
            "
            add rsp, 8
            iretq
            "
        );
    };
}

interrupt_no_error!(default_exception, stack, {
    log::info!("default exception\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(default_interrupt, stack, {
    log::info!("default interrupt\n");
    stack.dump();
    deadloop();
});

#[cfg(feature = "integration-test")]
interrupt_no_error!(divide_by_zero, stack, {
    log::info!("Divide by zero\n");
    crate::DIVIDED_BY_ZERO_EVENT_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    stack.iret.rip += 7;
    log::info!("divide_by_zero done\n");
    return;
});

#[cfg(not(feature = "integration-test"))]
interrupt_no_error!(divide_by_zero, stack, {
    log::info!("Divide by zero\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(debug, stack, {
    log::info!("Debug trap\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(non_maskable, stack, {
    log::info!("Non-maskable interrupt\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(breakpoint, stack, {
    log::info!("Breakpoint trap\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(overflow, stack, {
    log::info!("Overflow trap\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(bound_range, stack, {
    log::info!("Bound range exceeded fault\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(invalid_opcode, stack, {
    log::info!("Invalid opcode fault\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(device_not_available, stack, {
    log::info!("Device not available fault\n");
    stack.dump();
    deadloop();
});

interrupt_error!(double_fault, stack, {
    log::info!("Double fault\n");
    stack.dump();
    deadloop();
});

interrupt_error!(invalid_tss, stack, {
    log::info!("Invalid TSS fault\n");
    stack.dump();
    deadloop();
});

interrupt_error!(segment_not_present, stack, {
    log::info!("Segment not present fault\n");
    stack.dump();
    deadloop();
});

interrupt_error!(stack_segment, stack, {
    log::info!("Stack segment fault\n");
    stack.dump();
    deadloop();
});

interrupt_error!(protection, stack, {
    log::info!("Protection fault\n");
    stack.dump();
    deadloop();
});

interrupt_error!(page, stack, {
    let cr2: usize;
    asm!("mov {}, cr2",  out(reg) cr2);
    log::info!("Page fault: {:>016X}\n", cr2);
    stack.dump();
    deadloop();
});

interrupt_no_error!(fpu, stack, {
    log::info!("FPU floating point fault\n");
    stack.dump();
    deadloop();
});

interrupt_error!(alignment_check, stack, {
    log::info!("Alignment check fault\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(machine_check, stack, {
    log::info!("Machine check fault\n");
    stack.dump();
    deadloop();
});

interrupt_no_error!(simd, stack, {
    log::info!("SIMD floating point fault\n");
    stack.dump();
    deadloop();
});

#[cfg(feature = "tdx")]
const EXIT_REASON_CPUID: u32 = 10;
#[cfg(feature = "tdx")]
const EXIT_REASON_HLT: u32 = 12;
#[cfg(feature = "tdx")]
const EXIT_REASON_RDPMC: u32 = 15;
#[cfg(feature = "tdx")]
const EXIT_REASON_VMCALL: u32 = 18;
#[cfg(feature = "tdx")]
const EXIT_REASON_IO_INSTRUCTION: u32 = 30;
#[cfg(feature = "tdx")]
const EXIT_REASON_MSR_READ: u32 = 31;
#[cfg(feature = "tdx")]
const EXIT_REASON_MSR_WRITE: u32 = 32;
#[cfg(feature = "tdx")]
const EXIT_REASON_MWAIT_INSTRUCTION: u32 = 36;
#[cfg(feature = "tdx")]
const EXIT_REASON_MONITOR_INSTRUCTION: u32 = 39;
#[cfg(feature = "tdx")]
const EXIT_REASON_WBINVD: u32 = 54;

#[cfg(feature = "tdx")]
interrupt_no_error!(virtualization, stack, {
    // Firstly get VE information from TDX module, halt it error occurs
    let ve_info = tdx::tdcall_get_ve_info().expect("#VE handler: fail to get VE info\n");

    match ve_info.exit_reason {
        EXIT_REASON_HLT => {
            tdx::tdvmcall_halt();
        }
        EXIT_REASON_IO_INSTRUCTION => {
            if !handle_tdx_ioexit(&ve_info, stack) {
                tdx::tdvmcall_halt();
            }
        }
        EXIT_REASON_MSR_READ => {
            let msr = tdx::tdvmcall_rdmsr(stack.scratch.rcx as u32);
            stack.scratch.rax = (msr as u32 & u32::MAX) as usize; // EAX
            stack.scratch.rdx = ((msr >> 32) as u32 & u32::MAX) as usize; // EDX
        }
        EXIT_REASON_MSR_WRITE => {
            let data = stack.scratch.rax as u64 | ((stack.scratch.rdx as u64) << 32); // EDX:EAX
            tdx::tdvmcall_wrmsr(stack.scratch.rcx as u32, data);
        }
        EXIT_REASON_CPUID => {
            let cpuid = tdx::tdvmcall_cpuid(stack.scratch.rax as u32, stack.scratch.rcx as u32);
            let mask = 0xFFFF_FFFF_0000_0000_usize;
            stack.scratch.rax = (stack.scratch.rax & mask) | cpuid.eax as usize;
            stack.preserved.rbx = (stack.preserved.rbx & mask) | cpuid.ebx as usize;
            stack.scratch.rcx = (stack.scratch.rcx & mask) | cpuid.ecx as usize;
            stack.scratch.rdx = (stack.scratch.rdx & mask) | cpuid.edx as usize;
        }
        EXIT_REASON_VMCALL
        | EXIT_REASON_MWAIT_INSTRUCTION
        | EXIT_REASON_MONITOR_INSTRUCTION
        | EXIT_REASON_WBINVD
        | EXIT_REASON_RDPMC => return,
        // Unknown
        // And currently CPUID and MMIO handler is not implemented
        // Only VMCall is supported
        _ => {
            log::warn!("Unsupported #VE exit reason {:#x} ", ve_info.exit_reason);
            log::info!("Virtualization fault\n");
            stack.dump();
            deadloop();
        }
    };

    stack.iret.rip += ve_info.exit_instruction_length as usize;

    // If CET shadow stack is enabled, processor will compare the `LIP` value saved in the shadow
    // stack and the `RIP` value saved in the normal stack when executing a return from an
    // exception handler and cause a control protection exception if they do not match.
    #[cfg(feature = "cet-shstk")]
    {
        use x86_64::registers::control::{Cr4, Cr4Flags};
        use x86_64::registers::model_specific::Msr;

        const MSR_IA32_S_CET: u32 = 0x6A2;
        const SH_STK_EN: u64 = 1;
        const WR_SHSTK_E: u64 = 1 << 1;

        let mut msr_cet = Msr::new(MSR_IA32_S_CET);

        // If shadow stack is not enabled, return
        if (msr_cet.read() & SH_STK_EN) == 0
            || (Cr4::read() & Cr4Flags::CONTROL_FLOW_ENFORCEMENT).is_empty()
        {
            return;
        }

        // Read the Shadow Stack Pointer
        let mut ssp: u64;
        asm!(
            "rdsspq {ssp}",
            ssp = out(reg) ssp,
        );

        // SSP -> Return address of current function | SSP | LIP | CS
        let lip_ptr = ssp + 0x10;
        let lip = *(lip_ptr as *const u64) + ve_info.exit_instruction_length as u64;

        // Enables the WRSSD/WRSSQ instructions by setting the `WR_SHSTK_E`
        // to 1, then we can write the shadow stack
        msr_cet.write(msr_cet.read() | WR_SHSTK_E);

        // Write the new LIP to the shadow stack
        asm!(
            "wrssq [{lip_ptr}], {lip}",
            lip_ptr = in(reg) lip_ptr,
            lip = in(reg) lip,
        );

        // Clear the `WR_SHSTK_E`
        msr_cet.write(msr_cet.read() & !WR_SHSTK_E);
    }
});

// Handle IO exit from TDX Module
//
// Use TDVMCALL to realize IO read/write operation
// Return false if VE info is invalid
#[cfg(feature = "tdx")]
fn handle_tdx_ioexit(ve_info: &tdx::TdVeInfo, stack: &mut InterruptNoErrorStack) -> bool {
    let size = ((ve_info.exit_qualification & 0x7) + 1) as usize; // 0 - 1bytes, 1 - 2bytes, 3 - 4bytes
    let read = (ve_info.exit_qualification >> 3) & 0x1 == 1;
    let string = (ve_info.exit_qualification >> 4) & 0x1 == 1;
    let _operand = (ve_info.exit_qualification >> 6) & 0x1 == 0; // 0 = DX, 1 = immediate
    let port = (ve_info.exit_qualification >> 16) as u16;
    let repeat = if (ve_info.exit_qualification >> 5) & 0x1 == 1 {
        stack.scratch.rcx
    } else {
        0
    };

    // Size of access should be 1/2/4 bytes
    if size != 1 && size != 2 && size != 4 {
        return false;
    }

    // Define closure to perform IO port read with different size operands
    let io_read = |size, port| match size {
        1 => tdx::tdvmcall_io_read_8(port) as u32,
        2 => tdx::tdvmcall_io_read_16(port) as u32,
        4 => tdx::tdvmcall_io_read_32(port) as u32,
        _ => 0,
    };

    // Define closure to perform IO port write with different size operands
    let io_write = |size, port, data| match size {
        1 => tdx::tdvmcall_io_write_8(port, data as u8),
        2 => tdx::tdvmcall_io_write_16(port, data as u16),
        4 => tdx::tdvmcall_io_write_32(port, data as u32),
        _ => {}
    };

    // INS / OUTS
    if string {
        for _ in 0..repeat {
            if read {
                let val = io_read(size, port);
                unsafe {
                    let rsi = core::slice::from_raw_parts_mut(
                        stack.scratch.rdi as *mut u8,
                        size as usize,
                    );
                    // Safety: size is smaller than 4
                    rsi.copy_from_slice(&u32::to_le_bytes(val)[..size])
                }
                stack.scratch.rdi += size as usize;
            } else {
                let mut val = 0;
                unsafe {
                    let rsi =
                        core::slice::from_raw_parts(stack.scratch.rsi as *mut u8, size as usize);
                    for (idx, byte) in rsi.iter().enumerate() {
                        val |= (*byte as u32) << (idx * 8);
                    }
                }
                io_write(size, port, val);
                stack.scratch.rsi += size as usize;
            }
            stack.scratch.rcx -= 1;
        }
    } else {
        if read {
            // Write the IO read result to the low $size-bytes of rax
            stack.scratch.rax = (stack.scratch.rax & !(2_usize.pow(size as u32 * 8) - 1))
                | (io_read(size, port) as usize & (2_usize.pow(size as u32 * 8) - 1));
        } else {
            io_write(size, port, stack.scratch.rax as u32);
        }
    }

    true
}

fn deadloop() {
    #[allow(clippy::empty_loop)]
    loop {
        x86_64::instructions::interrupts::enable();
        x86_64::instructions::hlt();
    }
}

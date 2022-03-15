// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "tdx")]
use tdx_tdcall::tdx;

// the order is aligned with scratch_push!() and scratch_pop!()
#[repr(C, packed)]
struct ScratchRegisters {
    r11: usize,
    r10: usize,
    r9: usize,
    r8: usize,
    rsi: usize,
    rdi: usize,
    rdx: usize,
    rcx: usize,
    rax: usize,
}

impl ScratchRegisters {
    fn dump(&self) {
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
struct PreservedRegisters {
    r15: usize,
    r14: usize,
    r13: usize,
    r12: usize,
    rbp: usize,
    rbx: usize,
}

impl PreservedRegisters {
    fn dump(&self) {
        log::info!("RBX:   {:>016X}\n", { self.rbx });
        log::info!("RBP:   {:>016X}\n", { self.rbp });
        log::info!("R12:   {:>016X}\n", { self.r12 });
        log::info!("R13:   {:>016X}\n", { self.r13 });
        log::info!("R14:   {:>016X}\n", { self.r14 });
        log::info!("R15:   {:>016X}\n", { self.r15 });
    }
}

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
struct IretRegisters {
    rip: usize,
    cs: usize,
    rflags: usize,
}

impl IretRegisters {
    fn dump(&self) {
        log::info!("RFLAG: {:>016X}\n", { self.rflags });
        log::info!("CS:    {:>016X}\n", { self.cs });
        log::info!("RIP:   {:>016X}\n", { self.rip });
    }
}

#[repr(packed)]
struct InterruptNoErrorStack {
    preserved: PreservedRegisters,
    scratch: ScratchRegisters,
    iret: IretRegisters,
}

impl InterruptNoErrorStack {
    fn dump(&self) {
        self.iret.dump();
        self.scratch.dump();
        self.preserved.dump();
    }
}

#[repr(packed)]
struct InterruptErrorStack {
    preserved: PreservedRegisters,
    scratch: ScratchRegisters,
    code: usize,
    iret: IretRegisters,
}

impl InterruptErrorStack {
    fn dump(&self) {
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
            iret
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
            iret
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
const OP_CODE_IN_AL_IMM8: u8 = 0xE4;
#[cfg(feature = "tdx")]
const OP_CODE_IN_EAX_IMM8: u8 = 0xE5;
#[cfg(feature = "tdx")]
const OP_CODE_IN_AL_DX: u8 = 0xEC;
#[cfg(feature = "tdx")]
const OP_CODE_IN_EAX_DX: u8 = 0xED;
#[cfg(feature = "tdx")]
const OP_CODE_OUT_IMM8_AL: u8 = 0xE6;
#[cfg(feature = "tdx")]
const OP_CODE_OUT_IMM8_EAX: u8 = 0xE7;
#[cfg(feature = "tdx")]
const OP_CODE_OUT_DX_AL: u8 = 0xEE;
#[cfg(feature = "tdx")]
const OP_CODE_OUT_DX_EAX: u8 = 0xEF;

#[cfg(feature = "tdx")]
interrupt_no_error!(virtualization, stack, {
    let op_code: u8 = *(stack.iret.rip as *const u8);
    match op_code {
        // IN
        OP_CODE_IN_AL_IMM8 => {
            // log::info!("<IN AL, IMM8> ")
            let port: u8 = *((stack.iret.rip + 1) as *const u8);
            let al = tdx::tdvmcall_io_read_8(port as u16);
            stack.scratch.rax = (stack.scratch.rax & 0xFFFF_FFFF_FFFF_FF00_usize) | al as usize;
            stack.iret.rip += 2;
            // log::info!("Fault done\n");
            return;
        }
        OP_CODE_IN_EAX_IMM8 => {
            // log::info!("<IN EAX, IMM8> ")
            let port: u8 = *((stack.iret.rip + 1) as *const u8);
            let eax = tdx::tdvmcall_io_read_32(port as u16);
            stack.scratch.rax = (stack.scratch.rax & 0xFFFF_FFFF_0000_0000_usize) | eax as usize;
            stack.iret.rip += 2;
            // log::info!("Fault done\n");
            return;
        }
        OP_CODE_IN_AL_DX => {
            // log::info!("<IN AL, DX> ");
            let al = tdx::tdvmcall_io_read_8((stack.scratch.rdx & 0xFFFF) as u16);
            stack.scratch.rax = (stack.scratch.rax & 0xFFFF_FFFF_FFFF_FF00_usize) | al as usize;
            stack.iret.rip += 1;
            // log::info!("Fault done\n");
            return;
        }
        OP_CODE_IN_EAX_DX => {
            // log::info!("<IN EAX, DX> ");
            let eax = tdx::tdvmcall_io_read_32((stack.scratch.rdx & 0xFFFF) as u16);
            stack.scratch.rax = (stack.scratch.rax & 0xFFFF_FFFF_0000_0000_usize) | eax as usize;
            stack.iret.rip += 1;
            // log::info!("Fault done\n");
            return;
        }
        // OUT
        OP_CODE_OUT_IMM8_AL => {
            // log::info!("<OUT IMM8, AL> ")
            let port: u8 = *((stack.iret.rip + 1) as *const u8);
            tdx::tdvmcall_io_write_8(port as u16, (stack.scratch.rax & 0xFF) as u8);
            stack.iret.rip += 2;
            // log::info!("Fault done\n");
            return;
        }
        OP_CODE_OUT_IMM8_EAX => {
            // log::info!("<OUT IMM8, EAX> ")
            let port: u8 = *((stack.iret.rip + 1) as *const u8);
            tdx::tdvmcall_io_write_32(port as u16, (stack.scratch.rax & 0xFFFF_FFFF) as u32);
            stack.iret.rip += 2;
            // log::info!("Fault done\n");
            return;
        }
        OP_CODE_OUT_DX_AL => {
            // log::info!("<OUT DX, AL> ");
            tdx::tdvmcall_io_write_8(
                (stack.scratch.rdx & 0xFFFF) as u16,
                (stack.scratch.rax & 0xFF) as u8,
            );
            stack.iret.rip += 1;
            // log::info!("Fault done\n");
            return;
        }
        OP_CODE_OUT_DX_EAX => {
            // log::info!("<OUT DX, EAX> ");
            tdx::tdvmcall_io_write_32(
                (stack.scratch.rdx & 0xFFFF) as u16,
                (stack.scratch.rax & 0xFFFF_FFFF) as u32,
            );
            stack.iret.rip += 1;
            // log::info!("Fault done\n");
            return;
        }
        // Unknown
        _ => log::warn!("unknown opcode: {:#x} ", op_code),
    };
    log::info!("Virtualization fault\n");
    stack.dump();
    deadloop();
});

#[cfg(feature = "tdx")]
fn deadloop() {
    // TBD: empty `loop {}` wastes CPU cycles
    #[allow(clippy::empty_loop)]
    loop {
        // TDX does not allow HLT instruction.
        // TDVMCALL<HLT> may be used here. TBD later.
        // x86_64::instructions::interrupts::enable();
        // x86_64::instructions::hlt();
    }
}

#[cfg(not(feature = "tdx"))]
fn deadloop() {
    #[allow(clippy::empty_loop)]
    loop {
        x86_64::instructions::interrupts::enable();
        x86_64::instructions::hlt();
    }
}

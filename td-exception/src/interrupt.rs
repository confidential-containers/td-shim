// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::arch::asm;
use spin::Mutex;
#[cfg(feature = "tdx")]
use tdx_tdcall::tdx;

use crate::{idt::IDT_ENTRY_COUNT, ExceptionError};

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
pub struct InterruptStack {
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    pub vector: usize,
    pub code: usize,
    pub iret: IretRegisters,
}

impl InterruptStack {
    pub fn dump(&self) {
        self.iret.dump();
        log::info!("CODE:  {:>016X}\n", { self.code });
        log::info!("VECTOR:  {:>016X}\n", { self.vector });
        self.scratch.dump();
        self.preserved.dump();
    }
}

#[derive(Debug, Copy, Clone)]
pub struct InterruptCallback {
    func: fn(&mut InterruptStack),
}

impl InterruptCallback {
    pub const fn new(func: fn(&mut InterruptStack)) -> Self {
        InterruptCallback { func }
    }
}

struct InterruptCallbackTable {
    table: [InterruptCallback; IDT_ENTRY_COUNT],
}

impl InterruptCallbackTable {
    const fn init() -> Self {
        InterruptCallbackTable {
            table: [InterruptCallback::new(default_callback); IDT_ENTRY_COUNT],
        }
    }
}

static CALLBACK_TABLE: Mutex<InterruptCallbackTable> = Mutex::new(InterruptCallbackTable::init());

pub(crate) fn init_interrupt_callbacks() {
    let mut callbacks = CALLBACK_TABLE.lock();
    // Set up exceptions handler according to Intel64 & IA32 Software Developer Manual
    // Reference: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    callbacks.table[0].func = divide_by_zero;
    callbacks.table[1].func = debug;
    callbacks.table[2].func = non_maskable;
    callbacks.table[3].func = breakpoint;
    callbacks.table[4].func = overflow;
    callbacks.table[5].func = bound_range;
    callbacks.table[6].func = invalid_opcode;
    callbacks.table[7].func = device_not_available;
    callbacks.table[8].func = double_fault;
    // 9 no longer available
    callbacks.table[10].func = invalid_tss;
    callbacks.table[11].func = segment_not_present;
    callbacks.table[12].func = stack_segment;
    callbacks.table[13].func = protection;
    callbacks.table[14].func = page;
    // 15 reserved
    callbacks.table[16].func = fpu;
    callbacks.table[17].func = alignment_check;
    callbacks.table[18].func = machine_check;
    callbacks.table[19].func = simd;
    #[cfg(feature = "tdx")]
    {
        callbacks.table[20].func = virtualization;
    }
    callbacks.table[21].func = control_flow;
}

pub fn register_interrupt_callback(
    index: usize,
    callback: InterruptCallback,
) -> Result<(), ExceptionError> {
    if index > IDT_ENTRY_COUNT {
        return Err(ExceptionError::InvalidParameter);
    }
    CALLBACK_TABLE.lock().table[index] = callback;
    Ok(())
}

fn eoi() {
    // Write the end-of-interrupt (EOI) register (0x80B) at the end of the handler
    // routine, sometime before the IRET instruction
    unsafe {
        asm!(
            "
            mov rcx, 0x80B
            mov edx, 0
            mov eax, 0
            wrmsr
        "
        )
    }
}

#[no_mangle]
fn generic_interrupt_handler(stack: &mut InterruptStack) {
    if stack.vector >= IDT_ENTRY_COUNT {
        log::error!("Invalid interrupt vector number!\n");
        return;
    }

    // We need to allow the re-entry of this handler. For example, virtualization exception may
    // happen in a timer interrupt handler. So we need to copy the function pointer out and
    // release the lock.
    let func = CALLBACK_TABLE.lock().table[stack.vector].func;
    func(stack);

    // If we are handling an interrupt, signal a end-of-interrupt before return.
    if stack.vector > 31 {
        eoi();
    }
}

fn default_callback(stack: &mut InterruptStack) {
    log::info!("default interrupt callback\n");
    stack.dump();
    deadloop();
}

#[cfg(feature = "integration-test")]
fn divide_by_zero(stack: &mut InterruptStack) {
    log::info!("Divide by zero\n");
    crate::DIVIDED_BY_ZERO_EVENT_COUNT.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    stack.iret.rip += 7;
    log::info!("divide_by_zero done\n");
    return;
}

#[cfg(not(feature = "integration-test"))]
fn divide_by_zero(stack: &mut InterruptStack) {
    log::info!("Divide by zero\n");
    stack.dump();
    deadloop();
}

fn debug(stack: &mut InterruptStack) {
    log::info!("Debug trap\n");
    stack.dump();
    deadloop();
}

fn non_maskable(stack: &mut InterruptStack) {
    log::info!("Non-maskable interrupt\n");
    stack.dump();
    deadloop();
}

fn breakpoint(stack: &mut InterruptStack) {
    log::info!("Breakpoint trap\n");
    stack.dump();
    deadloop();
}

fn overflow(stack: &mut InterruptStack) {
    log::info!("Overflow trap\n");
    stack.dump();
    deadloop();
}

fn bound_range(stack: &mut InterruptStack) {
    log::info!("Bound range exceeded fault\n");
    stack.dump();
    deadloop();
}

fn invalid_opcode(stack: &mut InterruptStack) {
    log::info!("Invalid opcode fault\n");
    stack.dump();
    deadloop();
}

fn device_not_available(stack: &mut InterruptStack) {
    log::info!("Device not available fault\n");
    stack.dump();
    deadloop();
}

fn double_fault(stack: &mut InterruptStack) {
    log::info!("Double fault\n");
    stack.dump();
    deadloop();
}

fn invalid_tss(stack: &mut InterruptStack) {
    log::info!("Invalid TSS fault\n");
    stack.dump();
    deadloop();
}

fn segment_not_present(stack: &mut InterruptStack) {
    log::info!("Segment not present fault\n");
    stack.dump();
    deadloop();
}

fn stack_segment(stack: &mut InterruptStack) {
    log::info!("Stack segment fault\n");
    stack.dump();
    deadloop();
}

fn protection(stack: &mut InterruptStack) {
    log::info!("Protection fault\n");
    stack.dump();
    deadloop();
}

fn page(stack: &mut InterruptStack) {
    let cr2: usize;
    unsafe {
        asm!("mov {}, cr2",  out(reg) cr2);
    }
    log::info!("Page fault: {:>016X}\n", cr2);
    stack.dump();
    deadloop();
}

fn fpu(stack: &mut InterruptStack) {
    log::info!("FPU floating point fault\n");
    stack.dump();
    deadloop();
}

fn alignment_check(stack: &mut InterruptStack) {
    log::info!("Alignment check fault\n");
    stack.dump();
    deadloop();
}

fn machine_check(stack: &mut InterruptStack) {
    log::info!("Machine check fault\n");
    stack.dump();
    deadloop();
}

fn simd(stack: &mut InterruptStack) {
    log::info!("SIMD floating point fault\n");
    stack.dump();
    deadloop();
}

fn control_flow(stack: &mut InterruptStack) {
    log::info!("Control Flow Exception\n");
    stack.dump();
    deadloop();
}

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
fn virtualization(stack: &mut InterruptStack) {
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
            let msr = tdx::tdvmcall_rdmsr(stack.scratch.rcx as u32)
                .expect("fail to perform RDMSR operation\n");
            stack.scratch.rax = (msr as u32 & u32::MAX) as usize; // EAX
            stack.scratch.rdx = ((msr >> 32) as u32 & u32::MAX) as usize; // EDX
        }
        EXIT_REASON_MSR_WRITE => {
            let data = stack.scratch.rax as u64 | ((stack.scratch.rdx as u64) << 32); // EDX:EAX
            tdx::tdvmcall_wrmsr(stack.scratch.rcx as u32, data)
                .expect("fail to perform WRMSR operation\n");
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
    unsafe {
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

        // SSP -> return address of func [virtualization]
        //        return address of func [generic_interrupt_handler]
        //        SSP
        //        LIP
        //        CS
        let lip_ptr = ssp + 0x18;
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
}

// Handle IO exit from TDX Module
//
// Use TDVMCALL to realize IO read/write operation
// Return false if VE info is invalid
#[cfg(feature = "tdx")]
fn handle_tdx_ioexit(ve_info: &tdx::TdVeInfo, stack: &mut InterruptStack) -> bool {
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
        4 => tdx::tdvmcall_io_read_32(port),
        _ => 0,
    };

    // Define closure to perform IO port write with different size operands
    let io_write = |size, port, data| match size {
        1 => tdx::tdvmcall_io_write_8(port, data as u8),
        2 => tdx::tdvmcall_io_write_16(port, data as u16),
        4 => tdx::tdvmcall_io_write_32(port, data),
        _ => {}
    };

    // INS / OUTS
    if string {
        for _ in 0..repeat {
            if read {
                let val = io_read(size, port);
                unsafe {
                    let rsi = core::slice::from_raw_parts_mut(stack.scratch.rdi as *mut u8, size);
                    // Safety: size is smaller than 4
                    rsi.copy_from_slice(&u32::to_le_bytes(val)[..size])
                }
                stack.scratch.rdi += size;
            } else {
                let mut val = 0;
                unsafe {
                    let rsi = core::slice::from_raw_parts(stack.scratch.rsi as *mut u8, size);
                    for (idx, byte) in rsi.iter().enumerate() {
                        val |= (*byte as u32) << (idx * 8);
                    }
                }
                io_write(size, port, val);
                stack.scratch.rsi += size;
            }
            stack.scratch.rcx -= 1;
        }
    } else if read {
        // Write the IO read result to the low $size-bytes of rax
        stack.scratch.rax = (stack.scratch.rax & !(2_usize.pow(size as u32 * 8) - 1))
            | (io_read(size, port) as usize & (2_usize.pow(size as u32 * 8) - 1));
    } else {
        io_write(size, port, stack.scratch.rax as u32);
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

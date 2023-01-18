// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Manipulate x86_64 Interrupt Descriptor Table (IDT).
//!
//! Setup a stub IDT for td-shim, which assumes 1:1 mapping between physical address and virtual
//! address in identity mapping mode.
//!
//! It also handles Virtualization Interrupt for Intel TDX technology.

use core::mem::{self, size_of};
use core::slice::from_raw_parts_mut;

use bitflags::bitflags;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::interrupt;

const IDT_ENTRY_COUNT: usize = 256;

extern "win64" {
    fn sidt_call(addr: usize);
    fn lidt_call(addr: usize);
    fn read_cs_call() -> u16;
}

lazy_static! {
    static ref INIT_IDT: Mutex<Idt> = Mutex::new(Idt::new());
}

#[repr(C, packed)]
pub struct DescriptorTablePointer {
    pub limit: u16,
    pub base: u64,
}

#[no_mangle]
/// # Safety
///
/// This function is unsafe because of the load_idtr()
pub unsafe fn init() {
    load_idtr(&INIT_IDT.lock().idtr());
}

/// # Safety
///
/// This function is unsafe because of the load_idtr()
pub unsafe fn register_handler(index: u8, func: unsafe extern "C" fn()) {
    INIT_IDT.lock().register_handler(index, func);
    load_idtr(&INIT_IDT.lock().idtr());
}

pub type IdtEntries = [IdtEntry; IDT_ENTRY_COUNT];

// 8 alignment required
#[repr(C, align(8))]
pub struct Idt {
    pub entries: IdtEntries,
}

impl Default for Idt {
    fn default() -> Self {
        Self::new()
    }
}

impl Idt {
    pub fn new() -> Self {
        let mut idt = Self {
            entries: [IdtEntry::new(); IDT_ENTRY_COUNT],
        };
        idt.init();
        idt
    }

    pub fn init(&mut self) {
        let current_idt = &mut self.entries;

        // Set up exceptions handler according to Intel64 & IA32 Software Developer Manual
        // Reference: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
        current_idt[0].set_func(interrupt::divide_by_zero as usize);
        current_idt[1].set_func(interrupt::debug as usize);
        current_idt[2].set_func(interrupt::non_maskable as usize);
        current_idt[3].set_func(interrupt::breakpoint as usize);
        current_idt[4].set_func(interrupt::overflow as usize);
        current_idt[5].set_func(interrupt::bound_range as usize);
        current_idt[6].set_func(interrupt::invalid_opcode as usize);
        current_idt[7].set_func(interrupt::device_not_available as usize);
        current_idt[8].set_func(interrupt::double_fault as usize);
        // 9 no longer available
        current_idt[9].set_func(interrupt::default_exception as usize);
        current_idt[10].set_func(interrupt::invalid_tss as usize);
        current_idt[11].set_func(interrupt::segment_not_present as usize);
        current_idt[12].set_func(interrupt::stack_segment as usize);
        current_idt[13].set_func(interrupt::protection as usize);
        current_idt[14].set_func(interrupt::page as usize);
        // 15 reserved
        current_idt[15].set_func(interrupt::default_exception as usize);
        current_idt[16].set_func(interrupt::fpu as usize);
        current_idt[17].set_func(interrupt::alignment_check as usize);
        current_idt[18].set_func(interrupt::machine_check as usize);
        current_idt[19].set_func(interrupt::simd as usize);
        #[cfg(feature = "tdx")]
        current_idt[20].set_func(interrupt::virtualization as usize);
        #[cfg(not(feature = "tdx"))]
        current_idt[20].set_func(interrupt::default_exception as usize);
        // reset exception reserved
        for i in 21..32 {
            current_idt[i].set_func(interrupt::default_exception as usize);
        }
        // Setup reset potential interrupt handler.
        for i in 32..IDT_ENTRY_COUNT {
            current_idt[i].set_func(interrupt::default_interrupt as usize);
        }
    }

    // Construct the Interrupt Descriptor Table Pointer (IDTR) based
    // on the base address and size of entries.
    pub fn idtr(&self) -> DescriptorTablePointer {
        let mut desc = DescriptorTablePointer { limit: 1, base: 0 };

        desc.limit = (self.entries.len() * mem::size_of::<IdtEntry>() - 1) as u16;
        desc.base = self.entries.as_ptr() as u64;

        desc
    }

    // Register function pointer into the #index slot of IDT
    pub fn register_handler(&mut self, index: u8, func: unsafe extern "C" fn()) {
        let current_idt = &mut self.entries;
        current_idt[index as usize].set_func(func as usize);
    }
}

bitflags! {
    pub struct IdtFlags: u8 {
        const PRESENT = 1 << 7;
        const RING_0 = 0 << 5;
        const RING_1 = 1 << 5;
        const RING_2 = 2 << 5;
        const RING_3 = 3 << 5;
        const SS = 1 << 4;
        const INTERRUPT = 0xE;
        const TRAP = 0xF;
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct IdtEntry {
    offsetl: u16,
    selector: u16,
    zero: u8,
    attribute: u8,
    offsetm: u16,
    offseth: u32,
    zero2: u32,
}

impl IdtEntry {
    pub const fn new() -> IdtEntry {
        IdtEntry {
            offsetl: 0,
            selector: 0,
            zero: 0,
            attribute: 0,
            offsetm: 0,
            offseth: 0,
            zero2: 0,
        }
    }

    pub fn set_flags(&mut self, flags: IdtFlags) {
        self.attribute = flags.bits;
    }

    pub fn set_offset(&mut self, selector: u16, base: usize) {
        self.selector = selector;
        self.offsetl = base as u16;
        self.offsetm = (base >> 16) as u16;
        self.offseth = (base >> 32) as u32;
    }

    // A function to set the offset more easily
    pub fn set_func(&mut self, func: usize) {
        self.set_flags(IdtFlags::PRESENT | IdtFlags::RING_0 | IdtFlags::INTERRUPT);
        self.set_offset(unsafe { read_cs_call() }, func as usize); // GDT_KERNEL_CODE 1u16
    }

    pub fn set_ist(&mut self, index: u8) {
        // IST: [2..0] of field zero
        self.zero = 0x07 & index;
    }
}

pub fn store_idtr() -> DescriptorTablePointer {
    let mut idtr = DescriptorTablePointer { limit: 0, base: 0 };
    unsafe {
        sidt_call(&mut idtr as *mut DescriptorTablePointer as usize);
    }
    idtr
}

/// Get the Interrupt Descriptor Table from the DescriptorTablePointer.
///
/// ### Safety
///
/// The caller needs to ensure/protect from:
/// - the DescriptorTablePointer is valid
/// - the lifetime of the return reference
/// - concurrent access to the returned reference
pub unsafe fn read_idt(idtr: &DescriptorTablePointer) -> &'static mut [IdtEntry] {
    let addr = idtr.base as *mut IdtEntry;
    let size = (idtr.limit + 1) as usize / size_of::<IdtEntry>();
    from_raw_parts_mut(addr, size)
}

/// Load DescriptorTablePointer `idtr` into the Interrupt Descriptor Table Register.
///
/// ### Safety
///
/// Caller needs to ensure that `idtr` is valid, otherwise behavior is undefined.
pub unsafe fn load_idtr(idtr: &DescriptorTablePointer) {
    lidt_call(idtr as *const DescriptorTablePointer as usize);
}

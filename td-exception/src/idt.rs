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
pub use x86_64::structures::DescriptorTablePointer;
use x86_64::{
    instructions::tables::lidt,
    registers::segmentation::{Segment, CS},
    VirtAddr,
};

use crate::asm::interrupt_handler_table;
use crate::interrupt::init_interrupt_callbacks;

pub(crate) const IDT_ENTRY_COUNT: usize = 256;

lazy_static! {
    static ref INIT_IDT: Mutex<Idt> = Mutex::new(Idt::new());
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
        let handler_table = unsafe { &interrupt_handler_table as *const u8 as usize };

        for (idx, idt) in current_idt.iter_mut().enumerate() {
            idt.set_func(handler_table + idx * 32);
        }

        init_interrupt_callbacks();
    }

    // Construct the Interrupt Descriptor Table Pointer (IDTR) based
    // on the base address and size of entries.
    pub fn idtr(&self) -> DescriptorTablePointer {
        DescriptorTablePointer {
            limit: (self.entries.len() * mem::size_of::<IdtEntry>() - 1) as u16,
            base: VirtAddr::new(self.entries.as_ptr() as u64),
        }
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
        // RING_0 is 0 << 5
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
        self.set_flags(IdtFlags::PRESENT | IdtFlags::INTERRUPT);
        self.set_offset(CS::get_reg().0, func); // GDT_KERNEL_CODE 1u16
    }

    pub fn set_ist(&mut self, index: u8) {
        // IST: [2..0] of field zero
        self.zero = 0x07 & index;
    }
}

pub fn store_idtr() -> DescriptorTablePointer {
    x86_64::instructions::tables::sidt()
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
    let addr = idtr.base.as_u64() as *mut IdtEntry;
    let size = (idtr.limit + 1) as usize / size_of::<IdtEntry>();
    from_raw_parts_mut(addr, size)
}

/// Load DescriptorTablePointer `idtr` into the Interrupt Descriptor Table Register.
///
/// ### Safety
///
/// Caller needs to ensure that `idtr` is valid, otherwise behavior is undefined.
pub unsafe fn load_idtr(idtr: &DescriptorTablePointer) {
    lidt(idtr)
}

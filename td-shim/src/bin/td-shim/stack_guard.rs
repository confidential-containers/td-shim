// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{mem::size_of, slice::from_raw_parts};
use lazy_static::lazy_static;
use spin::Mutex;
use td_exception::idt;
use x86::{
    bits64::task::TaskStateSegment, dtables::DescriptorTablePointer, segmentation::SegmentSelector,
    Ring,
};

use crate::memory::Memory;

//
// stack guard feature
//
// +-----------------+ <-- Stack Top
// |                 |
// |   Normal Stack  |
// |                 |
// +-----------------+
// |    Guard Page   | // Not-Present in page table
// +-----------------+
// | Exception Stack | // Used in exception handler, when normal stack overflows to guard page.
// +-----------------+
//

pub const STACK_GUARD_PAGE_SIZE: usize = 0x1000;
pub const STACK_EXCEPTION_PAGE_SIZE: usize = 0x1000;

// TSS occupies two GDT entries.
const TSS_DESC_SIZE: u16 = 2 * size_of::<GdtEntry>() as u16;
// For x86_64, and GDT with eight entries is defined in `ResetVector/Ia32/ReloadFlat32.asm`.
// And the TSS needs two GDT entries, so at least 10 GDT entries.
const MAX_GDT_SIZE: usize = 10;
// Avalible present TSS
const IA32_GDT_TYPE_TSS: u8 = 0x89;

lazy_static! {
    static ref GDT: Mutex<Gdt> = Mutex::new(Gdt {
        entries: [GdtEntry(0); MAX_GDT_SIZE],
    });
    static ref TSS: Mutex<TaskStateSegment> = Mutex::new(TaskStateSegment::new());
}

#[derive(Debug, Clone, Copy)]
struct GdtEntry(u64);

#[repr(align(8))]
struct Gdt {
    entries: [GdtEntry; MAX_GDT_SIZE],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct TssDescriptor {
    limit15_0: u16,
    base15_0: u16,
    base23_16: u8,
    r#type: u8,
    limit19_16_and_flags: u8,
    base31_24: u8,
    base63_32: u32,
    reserved: u32,
}

impl TssDescriptor {
    fn new(base: u64, limit: u32, r#type: u8) -> Self {
        TssDescriptor {
            limit15_0: (limit & 0xffff) as u16,
            base15_0: (base & 0xffff) as u16,
            base23_16: (base >> 16 & 0xff) as u8,
            r#type: r#type,
            limit19_16_and_flags: (limit >> 16 & 0xf) as u8,
            base31_24: (base >> 24 & 0xff) as u8,
            base63_32: (base >> 32 & 0xffff) as u32,
            reserved: 0,
        }
    }

    fn low(&self) -> u64 {
        (self.limit15_0 as u64)
            | (self.base15_0 as u64) << 16
            | (self.base23_16 as u64) << 32
            | (self.r#type as u64) << 40
            | (self.limit19_16_and_flags as u64) << 48
            | (self.base31_24 as u64) << 56
    }

    fn high(&self) -> u64 {
        self.base63_32 as u64
    }
}

fn store_gdtr() -> DescriptorTablePointer<GdtEntry> {
    let mut gdtr: DescriptorTablePointer<GdtEntry> = Default::default();
    unsafe { x86::dtables::sgdt(&mut gdtr) };
    gdtr
}

/// Get the Global Descriptor Table from the DescriptorTablePointer.
///
/// ### Safety
///
/// The caller needs to ensure/protect from:
/// - the DescriptorTablePointer is valid
/// - the lifetime of the return reference
/// - concurrent access to the returned reference
unsafe fn read_gdt(gdtr: &DescriptorTablePointer<GdtEntry>) -> &'static [GdtEntry] {
    let gdt_addr = gdtr.base;
    let gdt_size = (gdtr.limit + 1) as usize / size_of::<GdtEntry>();

    unsafe { from_raw_parts(gdtr.base, gdt_size) }
}

/// Load DescriptorTablePointer `idtr` into the Interrupt Descriptor Table Register.
///
/// ### Safey
///
/// Caller needs to ensure that `gdtr` is valid, otherwise behavior is undefined.
unsafe fn load_gdtr(gdtr: &DescriptorTablePointer<GdtEntry>) {
    x86::dtables::lgdt(gdtr);
}

fn setup_tss(exception_page_top: u64) {
    // Read the original GDT
    let mut gdtr = store_gdtr();
    let gdt_size = gdtr.limit + 1;
    let origin_gdt_table_size = (gdt_size / 8) as usize;
    assert_ne!(gdtr.base as *const _ as usize, 0);
    assert!(origin_gdt_table_size + TSS_DESC_SIZE as usize <= MAX_GDT_SIZE * size_of::<GdtEntry>());

    let mut gdt = GDT.lock();
    // Safe because the bootstrap code has initialized GDT and we have verified it just now.
    unsafe {
        let original_gdt_entries = read_gdt(&gdtr);
        // Copy the original GDT to the new GDT
        gdt.entries[0..origin_gdt_table_size as usize].copy_from_slice(original_gdt_entries);
    }

    // Setup the TSS and append the TSS desc to the GDT
    let mut tss = &mut *TSS.lock();
    tss.set_ist(0, exception_page_top);
    let tss_desc: TssDescriptor = TssDescriptor::new(
        tss as *const _ as u64,
        size_of::<TaskStateSegment>() as u32 - 1,
        IA32_GDT_TYPE_TSS,
    );
    let mut tss_desc_entry = &mut gdt.entries[origin_gdt_table_size..origin_gdt_table_size + 2];
    tss_desc_entry[0].0 = tss_desc.low();
    tss_desc_entry[1].0 = tss_desc.high();

    gdtr.base = &gdt.entries as *const _;
    gdtr.limit = gdt_size + TSS_DESC_SIZE - 1;
    // Safe because the `gdtr` is valid.
    unsafe { load_gdtr(&gdtr) };

    // load the tss selector into the task register
    let tss_sel = SegmentSelector::new(origin_gdt_table_size as u16, Ring::Ring0);
    unsafe { x86::task::load_tr(tss_sel) };
}

fn setup_idt() {
    let mut idtr = idt::store_idtr();
    // Safe because _start() ensures that td_exception::setup_exception_handlers() get called
    // before stack_guard_enable().
    unsafe {
        let mut idt_entries = idt::read_idt(&idtr);
        idt_entries[14].set_ist(1);
        idt::load_idtr(&idtr);
    }
}

/// Turn on the stack red zone to guard from stack overflow.
///
/// The GDT/IDT must have been initialized when calling this function.
pub fn stack_guard_enable(mem: &mut Memory) {
    let stack_addr = mem.layout.runtime_stack_base;
    let guard_page_addr = stack_addr + STACK_EXCEPTION_PAGE_SIZE as u64;
    let exception_page_top = guard_page_addr;

    assert!(guard_page_addr + (STACK_GUARD_PAGE_SIZE as u64) < mem.layout.runtime_stack_top);
    log::info!(
        "Stack Guard: guard page top {:x}, known good stack top {:x}\n",
        guard_page_addr,
        exception_page_top
    );
    mem.set_not_present(guard_page_addr, STACK_GUARD_PAGE_SIZE as u64);

    setup_idt();
    setup_tss(exception_page_top);
}

#[cfg(test)]
mod tests {
    use super::*;
    use td_layout::runtime::TD_PAYLOAD_STACK_SIZE;

    #[test]
    fn test_stack_guard_struct_size() {
        assert_eq!(size_of::<GdtEntry>(), 8);
        assert_eq!(size_of::<TssDescriptor>(), TSS_DESC_SIZE as usize);
        assert!(STACK_EXCEPTION_PAGE_SIZE + STACK_GUARD_PAGE_SIZE < TD_PAYLOAD_STACK_SIZE as usize);
    }
}

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::memory::Memory;
use core::{
    mem::size_of,
    slice::{from_raw_parts, from_raw_parts_mut},
};
use lazy_static::lazy_static;
use spin::Mutex;
use td_exception::{asm, idt, idt::Idt};
use x86::{
    bits64::segmentation,
    bits64::task::TaskStateSegment,
    dtables::DescriptorTablePointer,
    segmentation::{BuildDescriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentSelector},
    Ring,
};

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
const MAX_GDT_SIZE: usize = 10;
const TSS_DESC_SIZE: u16 = 16;
//Avalible present TSS
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
    pub entries: [GdtEntry; MAX_GDT_SIZE],
}

#[derive(Debug)]
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

fn read_gdt(gdtr: &DescriptorTablePointer<GdtEntry>) -> &'static [GdtEntry] {
    let gdt_addr = gdtr.base;
    let gdt_size = (gdtr.limit + 1) as usize / size_of::<GdtEntry>();

    unsafe { from_raw_parts(gdtr.base, gdt_size) }
}

fn load_gdtr(gdtr: &DescriptorTablePointer<GdtEntry>) {
    unsafe { x86::dtables::lgdt(gdtr) };
}

#[allow(unused)]
fn dump_idt() {
    let idtr = idt::store_idtr();
    let idt_entries = idt::read_idt(&idtr);

    log::info!("Dump IDT: {:x?}\n", idt_entries);
}

#[allow(unused)]
fn dump_gdt() {
    let gdtr = store_gdtr();
    let addr = gdtr.base;
    let size = gdtr.limit + 1;

    let gdt_entries = read_gdt(&gdtr);

    log::info!("Dump GDT: {:x?}\n", gdt_entries);
}

fn setup_tss(exception_page_top: u64) {
    // Read the original GDT
    let mut gdtr = store_gdtr();
    let gdt_size = gdtr.limit + 1;

    let original_gdt_entries = read_gdt(&gdtr);
    let origin_gdt_table_size = (gdt_size / 8) as usize;

    // Copy the original GDT to the new GDT
    let mut gdt = GDT.lock();
    gdt.entries[0..origin_gdt_table_size as usize].copy_from_slice(original_gdt_entries);
    gdtr.base = &gdt.entries as *const _;
    gdtr.limit = gdt_size + TSS_DESC_SIZE - 1;

    // Setup the TSS and append the TSS desc to the GDT
    let mut tss_desc_entry = &mut gdt.entries[origin_gdt_table_size..origin_gdt_table_size + 2];

    let mut tss = &mut *TSS.lock();

    tss.set_ist(0, exception_page_top);
    let tss_desc: TssDescriptor = TssDescriptor::new(
        tss as *const _ as u64,
        size_of::<TaskStateSegment>() as u32 - 1,
        IA32_GDT_TYPE_TSS,
    );

    tss_desc_entry[0].0 = tss_desc.low();
    tss_desc_entry[1].0 = tss_desc.high();

    load_gdtr(&gdtr);

    // load the tss selector into the task register
    let tss_sel = SegmentSelector::new(origin_gdt_table_size as u16, Ring::Ring0);

    unsafe {
        x86::task::load_tr(tss_sel);
    }
}

fn setup_idt() {
    let mut idtr = idt::store_idtr();
    let mut idt_entries = idt::read_idt(&idtr);

    idt_entries[14].set_ist(1);
    idt::load_idtr(&idtr);
}

pub fn stack_guard_enable(mem: &mut Memory) {
    let stack_addr = mem.layout.runtime_stack_base;
    let guard_page_addr = stack_addr + STACK_EXCEPTION_PAGE_SIZE as u64;
    let exception_page_top = guard_page_addr;

    log::info!(
        "Stack Guard: guard page top {:x}, known good stack top {:x}\n",
        guard_page_addr,
        exception_page_top
    );
    mem.set_not_present(guard_page_addr, STACK_GUARD_PAGE_SIZE as u64);

    setup_idt();
    setup_tss(exception_page_top);
}

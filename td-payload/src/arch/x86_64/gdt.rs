// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use bit_field::BitField;
use core::mem::size_of;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
use x86_64::structures::gdt::{Descriptor, DescriptorFlags, GlobalDescriptorTable};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

lazy_static! {
    pub static ref GDT: Mutex<GlobalDescriptorTable> = Mutex::new(GlobalDescriptorTable::new());
    pub static ref TSS: Mutex<TaskStateSegment> = Mutex::new(TaskStateSegment::new());
}

pub fn init_gdt() {
    let gdt = &mut *GDT.lock();
    unsafe {
        let _code32 = gdt.add_entry(Descriptor::UserSegment(
            DescriptorFlags::KERNEL_CODE32.bits(),
        ));
        let code = gdt.add_entry(Descriptor::kernel_code_segment());
        let _code_exception = gdt.add_entry(Descriptor::kernel_code_segment());
        let data = gdt.add_entry(Descriptor::kernel_data_segment());
        gdt.load_unsafe();

        CS::set_reg(code);
        DS::set_reg(data);
        ES::set_reg(data);
        SS::set_reg(data);
        FS::set_reg(data);
        GS::set_reg(data);

        init_tss(gdt);
    }
}

unsafe fn init_tss(gdt: &mut GlobalDescriptorTable) {
    let ptr = &mut *TSS.lock() as *const _ as u64;

    let mut low = DescriptorFlags::PRESENT.bits();
    // base
    low.set_bits(16..40, ptr.get_bits(0..24));
    low.set_bits(56..64, ptr.get_bits(24..32));
    // limit
    low.set_bits(0..16, (size_of::<TaskStateSegment>() - 1) as u64);
    // type
    low.set_bits(40..44, 0b1001);

    let mut high = 0;
    high.set_bits(0..32, ptr.get_bits(32..64));

    let tss_descriptor = Descriptor::SystemSegment(low, high);
    let tss_segment_selector = gdt.add_entry(tss_descriptor);

    gdt.load_unsafe();

    load_tss(tss_segment_selector);
}

pub fn tss_set_ist(index: u8, stack: u64) {
    unsafe {
        let tss = &mut *TSS.lock();
        tss.interrupt_stack_table[index as usize] = VirtAddr::new(stack);

        let gdt = &mut *GDT.lock();
        gdt.load_unsafe();
    }
}

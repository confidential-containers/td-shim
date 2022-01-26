// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![allow(unused)]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]

mod consts;
mod frame;
pub mod paging;
pub use consts::*;

use x86_64::{
    structures::paging::{OffsetPageTable, PageTable},
    PhysAddr, VirtAddr,
};

/// Initialize the page table management subsystem.
pub fn init() {
    frame::init();
}

/// Build page table to map guest physical addres range [0, system_memory_size), the top page table
/// page will be hosted at guest physical address `page_table_memory_base`.
pub fn setup_paging(page_table_memory_base: u64, system_memory_size: u64) {
    let mut pt = unsafe {
        OffsetPageTable::new(
            &mut *(page_table_memory_base as *mut PageTable),
            VirtAddr::new(PHYS_VIRT_OFFSET as u64),
        )
    };

    frame::FRAME_ALLOCATOR
        .lock()
        .reserve(page_table_memory_base);
    paging::create_mapping(
        &mut pt,
        PhysAddr::new(0),
        VirtAddr::new(0),
        PAGE_SIZE_DEFAULT as u64,
        system_memory_size,
    );
    paging::cr3_write();
}

#[cfg(test)]
use bootloader::{boot_info as info, entry_point, BootInfo};
#[cfg(test)]
entry_point!(kernel_main);
#[cfg(test)]
use test_lib::{init_heap, panic, serial_println, test_runner};

#[cfg(test)]
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    use core::ops::Deref;
    use rust_td_layout::RuntimeMemoryLayout;

    // turn the screen gray
    if let Some(framebuffer) = boot_info.framebuffer.as_mut() {
        for byte in framebuffer.buffer_mut() {
            *byte = 0x90;
        }
    }

    let memoryregions = boot_info.memory_regions.deref();
    let offset = boot_info.physical_memory_offset.into_option().unwrap();

    for usable in memoryregions.iter() {
        if usable.kind == info::MemoryRegionKind::Usable {
            init_heap((usable.start + offset) as usize, 0x10000);
            //     *FRAME_ALLOCATOR.lock() =
            //     BMFrameAllocator::new(TD_PAYLOAD_PAGE_TABLE_BASE as usize, PAGE_TABLE_SIZE);

            // // The first frame should've already been allocated to level 4 PT
            // unsafe { FRAME_ALLOCATOR.lock().alloc() };

            break;
        }
    }

    #[cfg(test)]
    test_main();

    loop {}
}

#[cfg(test)]
mod tests {

    #[test_case]
    fn test_create_paging() {
        assert!(true);
    }
}

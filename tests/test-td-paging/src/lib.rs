// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![cfg_attr(test, no_main)]
// The `custom_test_frameworks` feature allows the use of `#[test_case]` and `#![test_runner]`.
// Any function, const, or static can be annotated with `#[test_case]` causing it to be aggregated
// (like #[test]) and be passed to the test runner determined by the `#![test_runner]` crate
// attribute.
#![feature(default_alloc_error_handler)]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
// Reexport the test harness main function under a different symbol.
#![reexport_test_harness_main = "test_main"]

#[cfg(test)]
use bootloader::{boot_info, entry_point, BootInfo};
#[cfg(test)]
use core::ops::Deref;
#[cfg(test)]
use test_runner_client::{init_heap, serial_println, test_runner};

#[cfg(test)]
entry_point!(kernel_main);

#[cfg(test)]
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // turn the screen gray
    if let Some(framebuffer) = boot_info.framebuffer.as_mut() {
        for byte in framebuffer.buffer_mut() {
            *byte = 0x90;
        }
    }

    let memoryregions = boot_info.memory_regions.deref();
    let offset = boot_info.physical_memory_offset.into_option().unwrap();

    for usable in memoryregions.iter() {
        if usable.kind == boot_info::MemoryRegionKind::Usable {
            init_heap((usable.start + offset) as usize, 0x100000);
            break;
        }
    }

    serial_println!("Start to execute test cases...");
    test_main();
    panic!("Unexpected return from test_main()!!!");
}

#[cfg(test)]
mod tests {
    use td_layout::runtime;
    use td_paging::{reserve_page, PHYS_VIRT_OFFSET};
    use x86_64::{
        structures::paging::{OffsetPageTable, PageTable},
        VirtAddr,
    };

    const TD_PAYLOAD_PAGE_TABLE_BASE: u64 = 0x800000;
    /// Build page table to map guest physical addres range [0, system_memory_size), the top page table
    /// page will be hosted at guest physical address `page_table_memory_base`.
    pub fn setup_paging(page_table_memory_base: u64, system_memory_size: u64) {
        let mut pt = unsafe {
            OffsetPageTable::new(
                &mut *(page_table_memory_base as *mut PageTable),
                VirtAddr::new(PHYS_VIRT_OFFSET as u64),
            )
        };

        if page_table_memory_base > system_memory_size
            || page_table_memory_base < TD_PAYLOAD_PAGE_TABLE_BASE
            || page_table_memory_base
                > TD_PAYLOAD_PAGE_TABLE_BASE + runtime::TD_PAYLOAD_PAGE_TABLE_SIZE as u64
            || TD_PAYLOAD_PAGE_TABLE_BASE + runtime::TD_PAYLOAD_PAGE_TABLE_SIZE as u64
                > system_memory_size
        {
            panic!(
                "invalid parameters (0x{:x}, 0x{:x} to setup_paging()",
                page_table_memory_base, system_memory_size
            );
        }

        reserve_page(page_table_memory_base);

        // TODO: make this work. More work is needed to enable paging, basically need to duplicate
        // tdshim::memory::setup_paging()
        /*
        create_mapping(
            &mut pt,
            PhysAddr::new(0),
            VirtAddr::new(0),
            PAGE_SIZE_DEFAULT as u64,
            system_memory_size,
        );
        page_table::cr3_write();
         */
    }

    #[test_case]
    fn test_create_paging() {
        td_paging::init(
            TD_PAYLOAD_PAGE_TABLE_BASE,
            runtime::TD_PAYLOAD_PAGE_TABLE_SIZE as usize,
        );
        setup_paging(
            TD_PAYLOAD_PAGE_TABLE_BASE + 0x1000,
            TD_PAYLOAD_PAGE_TABLE_BASE + runtime::TD_PAYLOAD_PAGE_TABLE_SIZE as u64,
        );

        // TODO: add test cases for create_mapping_with_flags(), set_page_flags()
    }
}

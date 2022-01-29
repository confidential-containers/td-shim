// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
// The `custom_test_frameworks` feature allows the use of `#[test_case]` and `#![test_runner]`.
// Any function, const, or static can be annotated with `#[test_case]` causing it to be aggregated
// (like #[test]) and be passed to the test runner determined by the `#![test_runner]` crate
// attribute.
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
// Reexport the test harness main function under a different symbol.
#![reexport_test_harness_main = "test_main"]
#![cfg_attr(test, no_main)]

#[cfg(test)]
entry_point!(kernel_main);

#[cfg(test)]
use bootloader::{boot_info as info, entry_point, BootInfo};
#[cfg(test)]
use core::ops::Deref;
#[cfg(test)]
use test_lib::{init_heap, panic, serial_println, test_runner};

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
        if usable.kind == info::MemoryRegionKind::Usable {
            init_heap((usable.start + offset) as usize, 0x10000);
            break;
        }
    }

    serial_println!("Start to execute test cases...");
    test_main();
    panic!("Unexpected return from test_main()!!!");
}

#[cfg(test)]
mod tests {
    use td_layout::runtime::TD_PAYLOAD_PAGE_TABLE_BASE;
    use td_paging::PAGE_TABLE_SIZE;

    #[test_case]
    fn test_create_paging() {
        td_paging::init();
        td_paging::setup_paging(
            TD_PAYLOAD_PAGE_TABLE_BASE + 0x1000,
            TD_PAYLOAD_PAGE_TABLE_BASE + PAGE_TABLE_SIZE as u64,
        );

        // TODO: add test cases for setup_paging(), create_mapping_with_flags(), set_page_flags()
    }
}

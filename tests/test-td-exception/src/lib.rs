// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![cfg_attr(test, no_main)]
// The `custom_test_frameworks` feature allows the use of `#[test_case]` and `#![test_runner]`.
// Any function, const, or static can be annotated with `#[test_case]` causing it to be aggregated
// (like #[test]) and be passed to the test runner determined by the `#![test_runner]` crate
// attribute.
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
    use td_exception::{setup_exception_handlers, DIVIDED_BY_ZERO_EVENT_COUNT};

    #[test_case]
    fn test_divided_by_zero() {
        use core::sync::atomic::Ordering::Acquire;
        setup_exception_handlers();

        assert_eq!(DIVIDED_BY_ZERO_EVENT_COUNT.load(Acquire), 0);
        // TODO: make this work:)
        //let _ = 1 / DIVIDED_BY_ZERO_EVENT_COUNT.load(Acquire);
        //assert_eq!(DIVIDED_BY_ZERO_EVENT_COUNT.load(Acquire), 1);
    }
}

// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
use bootloader::{entry_point, BootInfo};
#[cfg(test)]
use core::ops::Deref;
#[cfg(test)]
use test_runner_client::{init_heap, panic, serial_println, test_runner};

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
        if usable.kind == bootloader::boot_info::MemoryRegionKind::Usable {
            init_heap((usable.start + offset) as usize, 0x100000);
            break;
        }
    }

    test_main();

    loop {}
}

/*
#[cfg(test)]
mod tests {

    #[test_case]
    fn trivial_assertion() {
        assert_eq!(1, 1);
    }

    #[test_case]
    fn test_json() {
        super::json_test();
    }
}
 */

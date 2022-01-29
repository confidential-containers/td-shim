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
    #[test_case]
    fn trivial_assertion() {
        assert_eq!(1, 1);
    }

    #[test_case]
    fn test_json() {
        td_payload::json_test();
    }

    #[cfg(feature = "tdx")]
    #[test_case]
    fn test_tdx_call() {
        use tdx_tdcall::tdx;

        let mut td_info = tdx::TdInfoReturnData {
            gpaw: 0,
            attributes: 0,
            max_vcpus: 0,
            num_vcpus: 0,
            rsvd: [0; 3],
        };
        tdx::tdcall_get_td_info(&mut td_info);

        log::info!("gpaw - {:?}\n", td_info.gpaw);
        log::info!("attributes - {:?}\n", td_info.attributes);
        log::info!("max_vcpus - {:?}\n", td_info.max_vcpus);
        log::info!("num_vcpus - {:?}\n", td_info.num_vcpus);
        log::info!("rsvd - {:?}\n", td_info.rsvd);

        assert!(td_info.gpaw > 32);
        assert!(td_info.max_vcpus > 0);
        assert!(td_info.num_vcpus > 0);
    }
}

// Copyright © 2019 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
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
#![cfg_attr(not(test), no_main)]
#![allow(unused)]

use core::mem::size_of;

use alloc::vec::Vec;
use scroll::{Pread, Pwrite};
use td_layout::RuntimeMemoryLayout;
use td_shim::e820::{E820Entry, E820Type};
use td_shim::{TD_ACPI_TABLE_HOB_GUID, TD_E820_TABLE_HOB_GUID};
use td_uefi_pi::hob;
use td_uefi_pi::pi;
use zerocopy::FromBytes;

#[macro_use]
extern crate alloc;

mod mp;
#[cfg(feature = "benches")]
mod stack;

mod asm;
extern "win64" {
    fn stack_guard_test();
}

const E820_TABLE_SIZE: usize = 128;
const PAYLOAD_HEAP_SIZE: usize = 0x400_0000;

#[cfg(not(test))]
mod payload_impl {
    use super::*;
    use core::ffi::c_void;
    use core::panic::PanicInfo;
    use td_layout::memslice;
    use td_layout::runtime::*;
    use td_uefi_pi::hob;

    #[cfg(feature = "benches")]
    use benchmark::ALLOCATOR;
    #[cfg(not(feature = "benches"))]
    use linked_list_allocator::LockedHeap;

    #[cfg(not(feature = "benches"))]
    #[global_allocator]
    pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

    fn init_heap(heap_start: usize, heap_size: usize) {
        #[cfg(feature = "benches")]
        {
            log::info!("init_heap benches");
            ALLOCATOR.init(heap_start, heap_size);
        }

        #[cfg(not(feature = "benches"))]
        unsafe {
            ALLOCATOR.lock().init(heap_start, heap_size);
        }
    }

    #[panic_handler]
    #[allow(clippy::empty_loop)]
    fn panic(_info: &PanicInfo) -> ! {
        log::info!("panic ... {:?}\n", _info);
        loop {}
    }

    #[no_mangle]
    #[cfg_attr(target_os = "uefi", export_name = "efi_main")]
    pub extern "C" fn _start(hob: *const c_void) -> ! {
        #[cfg(feature = "tdx")]
        {
            td_logger::init().expect("td-payload: failed to initialize tdx logger");
        }
        log::info!("Starting td-payload hob - {:p}\n", hob);
        log::info!("setup_exception_handlers done\n");

        let hob_list = hob::check_hob_integrity(unsafe {
            memslice::get_dynamic_mem_slice_mut(memslice::SliceType::PayloadHob, hob as usize)
        })
        .expect("Integrity check failed: invalid HOB list");
        hob::dump_hob(hob_list);

        // There is no heap at this moment, put the E820 table on the stack
        let mut memory_map = [E820Entry::default(); E820_TABLE_SIZE];
        get_memory_map(hob_list, &mut memory_map);

        let heap_base = find_heap_memory(&memory_map).expect("Cannot find memory for heap");
        log::info!("Init heap: {:X} - {:X}\n", heap_base, PAYLOAD_HEAP_SIZE);
        init_heap(heap_base, PAYLOAD_HEAP_SIZE);

        #[cfg(feature = "benches")]
        {
            stack::bench_stack(memory_layout);
        }

        #[cfg(feature = "tdx")]
        {
            use tdx_tdcall::tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE;
            //Dump TD Report
            let tdx_report =
                tdx_tdcall::tdreport::tdcall_report(&[0u8; TD_REPORT_ADDITIONAL_DATA_SIZE]);
            log::info!("{:?}", tdx_report);
        }

        //Test JSON function using no-std serd_json.
        td_payload::json_test();

        //Stack guard test
        unsafe { stack_guard_test() };

        //Memory Protection (WP & NX) test.
        mp::mp_test();

        unsafe {
            let pointer: *const u32 = 0x10000000000usize as *const core::ffi::c_void as *const u32;
            let data = *pointer;
            log::info!("test - data: {:x}", data);
        }

        panic!("td-payload: all tests finished and enters dead loop");
    }
}

fn get_acpi_tables(hob_list: &[u8]) -> Vec<&[u8]> {
    let mut acpi_tables: Vec<&[u8]> = Vec::new();
    let mut hob = hob_list;
    while let Some(guided_hob) =
        hob::get_next_extension_guid_hob(hob, TD_ACPI_TABLE_HOB_GUID.as_bytes())
    {
        if let Some(guided_data) = hob::get_guid_data(guided_hob) {
            acpi_tables.push(guided_data);
        }
        if let Some(next) = hob::seek_to_next_hob(hob) {
            hob = next;
        } else {
            break;
        }
    }
    acpi_tables
}

fn get_memory_map(hob_list: &[u8], e820: &mut [E820Entry]) {
    if let Some(hob) = hob::get_next_extension_guid_hob(hob_list, TD_E820_TABLE_HOB_GUID.as_bytes())
    {
        let table = hob::get_guid_data(hob).expect("Failed to get data from E820 GUID HOB");
        let entry_num = table.len() / size_of::<E820Entry>();
        if entry_num > E820_TABLE_SIZE {
            panic!("Invalid E820 table size");
        }

        let mut offset = 0;
        let mut idx = 0;
        while idx < entry_num {
            if let Some(entry) =
                E820Entry::read_from(&table[offset..offset + size_of::<E820Entry>()])
            {
                // Ignore the padding zero in GUIDed HOB
                if idx == entry_num - 1 && entry == E820Entry::default() {
                    return;
                }
                // save it to table
                e820[idx] = entry;
                idx += 1;
                offset += size_of::<E820Entry>();
            } else {
                panic!("Error parsing E820 table\n");
            }
        }
    } else {
        panic!("There's no E820 table can be found in Payload HOB\n");
    }
}

fn find_heap_memory(memory_map: &[E820Entry]) -> Option<usize> {
    let mut target = None;
    // Find the highest usable memory for heap
    for entry in memory_map {
        if entry.r#type == E820Type::Memory as u32 && entry.size >= PAYLOAD_HEAP_SIZE as u64 {
            target = Some(entry);
        }
    }
    if let Some(entry) = target {
        return Some((entry.addr + entry.size) as usize - PAYLOAD_HEAP_SIZE);
    }
    None
}

#[cfg(test)]
fn main() {}

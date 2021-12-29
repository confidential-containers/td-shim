// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![no_std]
#![no_main]
#![allow(unused)]
#![feature(alloc_error_handler)]
#[macro_use]

mod lib;
mod tdinfo;
mod memslice;

extern crate alloc;
use core::ffi::c_void;
use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;
use tdx_tdcall::tdx;

use crate::lib::{TestSuite, TestResult};
use crate::tdinfo::Tdinfo;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;

use uefi_pi::hob_lib;

#[cfg(not(test))]
#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    log::info!("panic ... {:?}\n", _info);
    loop {}
}

#[alloc_error_handler]
#[allow(clippy::empty_loop)]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    log::info!("alloc_error ... {:?}\n", _info);
    panic!("deadloop");
}

#[cfg(not(test))]
#[global_allocator]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(test))]
pub fn init_heap(heap_start: usize, heap_size: usize) {
    unsafe {
        ALLOCATOR.lock().init(heap_start, heap_size);
    }
}

#[cfg(not(test))]
#[no_mangle]
#[cfg_attr(target_os = "uefi", export_name = "efi_main")]
pub extern "win64" fn _start(hob: *const c_void) -> ! {
    use rust_td_layout::runtime::*;

    tdx_logger::init();
    log::info!("Starting rust-tdcall-payload hob - {:p}\n", hob);

    // init heap so that we can allocate memory
    let hob_buffer =
        memslice::get_dynamic_mem_slice_mut(memslice::SliceType::PayloadHob, hob as usize);

    let hob_size = hob_lib::get_hob_total_size(hob_buffer).unwrap();
    let hob_list = &hob_buffer[..hob_size];

    init_heap(
        (hob_lib::get_system_memory_size_below_4gb(hob_list).unwrap() as usize
            - (TD_PAYLOAD_HOB_SIZE
                + TD_PAYLOAD_STACK_SIZE
                + TD_PAYLOAD_SHADOW_STACK_SIZE
                + TD_PAYLOAD_ACPI_SIZE
                + TD_PAYLOAD_EVENT_LOG_SIZE) as usize
            - TD_PAYLOAD_HEAP_SIZE as usize),
        TD_PAYLOAD_HEAP_SIZE as usize,
    );

    // create TestSuite to hold the test cases
    let mut ts = TestSuite {
        testsuite: Vec::new(),
        done_cases: 0,
        failed_cases: 0
    };

    // now we can create test case and put it to TestSuite
    // test Tdinfo
    let mut tdinfo = Tdinfo {
        name: String::from("Tdinfo"),
        hob: hob,
        result: TestResult::Error
    };
    ts.testsuite.push(Box::new(tdinfo));

    // run the TestSuite which contains the test cases
    log::info!("Start to run tests.\n");
    log::info!("---------------------------------------------\n");
    ts.run();
    log::info!("Total: {0}, Done: {1}, Failed: {2}\n", ts.testsuite.len(), ts.done_cases, ts.failed_cases);

    panic!("deadloop");
}

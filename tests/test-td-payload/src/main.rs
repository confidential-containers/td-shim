// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![no_main]
#![allow(unused)]
#![feature(alloc_error_handler)]
#[macro_use]

mod lib;
mod testacpi;
mod testiorw32;
mod testiorw8;
mod testmemmap;
mod testtdinfo;
mod testtdreport;
mod testtdve;

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;
use td_layout::memslice;

use crate::lib::{TestResult, TestSuite};
use crate::testacpi::{TdAcpi, TestTdAcpi};
use crate::testiorw32::Tdiorw32;
use crate::testiorw8::Tdiorw8;
use crate::testmemmap::MemoryMap;
use crate::testtdinfo::Tdinfo;
use crate::testtdreport::Tdreport;
use crate::testtdve::TdVE;

use r_efi::efi::Guid;
use serde::{Deserialize, Serialize};
use serde_json::{Result, Value};
use td_uefi_pi::{fv, hob, pi};

#[derive(Debug, Serialize, Deserialize)]
// The test cases' data structure corresponds to the test config json data structure
pub struct TestCases {
    pub tcs001: Tdinfo,
    pub tcs002: Tdinfo,
    pub tcs003: Tdinfo,
    pub tcs004: Tdreport,
    pub tcs005: Tdiorw8,
    pub tcs006: Tdiorw32,
    pub tcs007: TdVE,
    pub tcs008: TdAcpi,
    pub tcs009: MemoryMap,
}

pub const CFV_FFS_HEADER_TEST_CONFIG_GUID: Guid = Guid::from_fields(
    0xf10e684e,
    0x3abd,
    0x20e4,
    0x59,
    0x32,
    &[0x8f, 0x97, 0x3c, 0x35, 0x5e, 0x57],
); // {F10E684E-3ABD-20E4-5932-8F973C355E57}

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
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(test))]
fn init_heap(heap_start: usize, heap_size: usize) {
    unsafe {
        ALLOCATOR.lock().init(heap_start, heap_size);
    }
}

#[cfg(not(test))]
fn build_testcases() -> TestCases {
    log::info!("Starting get test data from cfv and parse json data\n");
    let cfv = memslice::get_mem_slice(memslice::SliceType::Config);
    let json_data = fv::get_file_from_fv(
        cfv,
        pi::fv::FV_FILETYPE_RAW,
        CFV_FFS_HEADER_TEST_CONFIG_GUID,
    )
    .unwrap();
    let json_string = String::from_utf8_lossy(json_data).to_string();
    // trim zero in json string
    let json_config = json_string.trim_matches(char::from(0));

    serde_json::from_str(json_config).unwrap()
}

#[cfg(not(test))]
#[no_mangle]
#[cfg_attr(target_os = "uefi", export_name = "efi_main")]
extern "win64" fn _start(hob: *const c_void) -> ! {
    use td_layout::runtime::*;
    use testmemmap::TestMemoryMap;

    td_logger::init();
    log::info!("Starting rust-tdcall-payload hob - {:p}\n", hob);

    // init heap so that we can allocate memory
    let hob_buffer = unsafe {
        memslice::get_dynamic_mem_slice_mut(memslice::SliceType::PayloadHob, hob as usize)
    };

    let hob_size = hob::get_hob_total_size(hob_buffer).unwrap();
    let hob_list = &hob_buffer[..hob_size];

    init_heap(
        (hob::get_system_memory_size_below_4gb(hob_list).unwrap() as usize
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
        passed_cases: 0,
        failed_cases: 0,
    };

    // build test cases with test configuration data in CFV
    let mut tcs = build_testcases();

    // Add test cases in ts.testsuite
    if tcs.tcs001.run {
        ts.testsuite.push(Box::new(tcs.tcs001));
    }

    if tcs.tcs002.run {
        ts.testsuite.push(Box::new(tcs.tcs002));
    }

    if tcs.tcs003.run {
        ts.testsuite.push(Box::new(tcs.tcs003));
    }

    if tcs.tcs004.run {
        ts.testsuite.push(Box::new(tcs.tcs004));
    }

    if tcs.tcs005.run {
        ts.testsuite.push(Box::new(tcs.tcs005));
    }

    if tcs.tcs006.run {
        ts.testsuite.push(Box::new(tcs.tcs006));
    }

    if tcs.tcs008.run && tcs.tcs008.expected.num > 0 {
        let test_acpi = TestTdAcpi {
            hob_address: hob as usize,
            td_acpi: tcs.tcs008,
        };
        ts.testsuite.push(Box::new(test_acpi));
    }

    if tcs.tcs009.run {
        let test_memory_map = TestMemoryMap {
            hob_address: hob as usize,
            case: tcs.tcs009,
        };
        ts.testsuite.push(Box::new(test_memory_map));
    }

    if tcs.tcs007.run {
        ts.testsuite.push(Box::new(tcs.tcs007));
    }

    // run the TestSuite which contains the test cases
    log::info!("---------------------------------------------\n");
    log::info!("Start to run tests.\n");
    log::info!("---------------------------------------------\n");
    ts.run();
    log::info!(
        "Test Result: Total run {0} tests; {1} passed; {2} failed\n",
        ts.testsuite.len(),
        ts.passed_cases,
        ts.failed_cases
    );

    panic!("deadloop");
}

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![no_main]
#![allow(unused)]
#[macro_use]

mod lib;
mod testacpi;
mod testcetibt;
mod testcetshstk;
mod testiorw32;
mod testiorw8;
mod testmemmap;
mod testmsrrw;
mod teststackguard;
mod testtdinfo;
mod testtdreport;
mod testtdve;
mod testtrustedboot;

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;
use td_layout::memslice;

use crate::lib::{TestResult, TestSuite};
use crate::testacpi::{TdAcpi, TestTdAcpi};
use crate::testcetibt::TestCetIbt;
use crate::testcetshstk::TestCetShstk;
use crate::testiorw32::Tdiorw32;
use crate::testiorw8::Tdiorw8;
use crate::testmemmap::MemoryMap;
use crate::testmsrrw::Tdmsrrw;
use crate::teststackguard::TestStackGuard;
use crate::testtdinfo::Tdinfo;
use crate::testtdreport::Tdreport;
use crate::testtdve::TdVE;
use crate::testtrustedboot::{TdTrustedBoot, TestTdTrustedBoot};

use r_efi::efi::Guid;
use serde::{Deserialize, Serialize};
use serde_json::{Result, Value};
use td_payload as _;
use td_payload::print;
use td_shim::e820::{E820Entry, E820Type};
use td_shim::{TD_ACPI_TABLE_HOB_GUID, TD_E820_TABLE_HOB_GUID};
use td_shim_interface::td_uefi_pi::{fv, hob, pi};
use zerocopy::FromBytes;

const E820_TABLE_SIZE: usize = 128;
const PAYLOAD_HEAP_SIZE: usize = 0x100_0000;

#[derive(Debug, Serialize, Deserialize)]
// The test cases' data structure corresponds to the test config json data structure
pub struct TestCases {
    pub tcs001: Tdinfo,
    pub tcs002: Tdinfo,
    pub tcs003: Tdinfo,
    pub tcs004: Tdinfo,
    pub tcs006: Tdreport,
    pub tcs007: Tdiorw8,
    pub tcs008: Tdiorw32,
    pub tcs009: TdVE,
    pub tcs010: TdAcpi,
    pub tcs011: MemoryMap,
    pub tcs012: MemoryMap,
    pub tcs013: MemoryMap,
    pub tcs014: MemoryMap,
    pub tcs015: MemoryMap,
    pub tcs016: TdTrustedBoot,
    pub tcs017: Option<TestStackGuard>,
    pub tcs018: Option<TestCetShstk>,
    pub tcs019: Option<TestCetIbt>,
    pub tcs020: Tdmsrrw,
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

/// The entry point of Payload
///
/// For the x86_64-unknown-uefi target, the entry point name is 'efi_main'
/// For the x86_64-unknown-none target, the entry point name is '_start'
#[no_mangle]
#[cfg(not(test))]
#[cfg_attr(target_os = "uefi", export_name = "efi_main")]
pub extern "C" fn _start(hob: u64, _payload: u64) -> ! {
    use td_payload::arch;
    use td_payload::mm::layout;

    extern "C" {
        fn main();
    }

    const PAGE_TABLE_SIZE: usize = 0x2800000;

    let layout = layout::RuntimeLayout {
        heap_size: layout::DEFAULT_HEAP_SIZE,
        stack_size: layout::DEFAULT_STACK_SIZE,
        page_table_size: PAGE_TABLE_SIZE,
        shared_memory_size: layout::DEFAULT_SHARED_MEMORY_SIZE,
        shadow_stack_size: layout::DEFAULT_SHADOW_STACK_SIZE,
    };

    arch::init::pre_init(hob, &layout, false);
    arch::init::init(&layout, main);
}

#[cfg(not(test))]
#[no_mangle]
extern "C" fn main() -> ! {
    use td_payload::hob::get_hob;
    use testmemmap::TestMemoryMap;

    let _ = td_logger::init();
    let hob = get_hob().expect("Failed to get payload HOB").as_ptr() as u64;

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

    if tcs.tcs006.run {
        ts.testsuite.push(Box::new(tcs.tcs006));
    }

    if tcs.tcs007.run {
        ts.testsuite.push(Box::new(tcs.tcs007));
    }

    if tcs.tcs008.run {
        ts.testsuite.push(Box::new(tcs.tcs008));
    }

    if tcs.tcs009.run {
        ts.testsuite.push(Box::new(tcs.tcs009));
    }

    if tcs.tcs010.run && tcs.tcs010.expected.num > 0 {
        let test_acpi = TestTdAcpi {
            hob_address: hob as usize,
            td_acpi: tcs.tcs010,
        };
        ts.testsuite.push(Box::new(test_acpi));
    }

    if tcs.tcs011.run {
        let test_memory_map = TestMemoryMap {
            hob_address: hob as usize,
            case: tcs.tcs011,
        };
        ts.testsuite.push(Box::new(test_memory_map));
    }

    if tcs.tcs012.run {
        let test_memory_map = TestMemoryMap {
            hob_address: hob as usize,
            case: tcs.tcs012,
        };
        ts.testsuite.push(Box::new(test_memory_map));
    }

    if tcs.tcs013.run {
        let test_memory_map = TestMemoryMap {
            hob_address: hob as usize,
            case: tcs.tcs013,
        };
        ts.testsuite.push(Box::new(test_memory_map));
    }

    if tcs.tcs014.run {
        let test_memory_map = TestMemoryMap {
            hob_address: hob as usize,
            case: tcs.tcs014,
        };
        ts.testsuite.push(Box::new(test_memory_map));
    }

    if tcs.tcs015.run {
        let test_memory_map = TestMemoryMap {
            hob_address: hob as usize,
            case: tcs.tcs015,
        };
        ts.testsuite.push(Box::new(test_memory_map));
    }

    if tcs.tcs016.run {
        let test_tboot = TestTdTrustedBoot {
            hob_address: hob as usize,
            case: tcs.tcs016,
        };
        ts.testsuite.push(Box::new(test_tboot));
    }

    if let Some(tcs017) = tcs.tcs017 {
        if tcs017.run {
            ts.testsuite.push(Box::new(tcs017));
        }
    }

    if let Some(tcs018) = tcs.tcs018 {
        if tcs018.run {
            ts.testsuite.push(Box::new(tcs018));
        }
    }

    if let Some(tcs019) = tcs.tcs019 {
        if tcs019.run {
            ts.testsuite.push(Box::new(tcs019));
        }
    }

    if tcs.tcs020.run {
        ts.testsuite.push(Box::new(tcs.tcs020));
    }

    // run the TestSuite which contains the test cases
    print!("---------------------------------------------\n");
    print!("Start to run tests.\n");
    print!("---------------------------------------------\n");
    ts.run();
    print!(
        "Test Result: Total run {0} tests; {1} passed; {2} failed\n",
        ts.testsuite.len(),
        ts.passed_cases,
        ts.failed_cases
    );

    // Need to set DEFAULT_SHARED_MEMORY_SIZE to 0x200000 before build
    #[cfg(all(feature = "coverage", feature = "tdx"))]
    {
        const MAX_COVERAGE_DATA_PAGE_COUNT: usize = 0x200;
        let mut shared = td_payload::mm::shared::SharedMemory::new(MAX_COVERAGE_DATA_PAGE_COUNT)
            .expect("New shared memory fail.");
        let buffer = shared.as_mut_bytes();
        let coverage_len = minicov::get_coverage_data_size();
        assert!(coverage_len < MAX_COVERAGE_DATA_PAGE_COUNT * td_paging::PAGE_SIZE);
        minicov::capture_coverage_to_buffer(&mut buffer[0..coverage_len]);
        print!(
            "coverage addr: {:x}, coverage len: {}",
            buffer.as_ptr() as u64,
            coverage_len
        );

        loop {}
    }

    panic!("deadloop");
}

#[cfg(test)]
fn main() {}
// FIXME: remove when https://github.com/Amanieu/minicov/issues/12 is fixed.
#[cfg(all(feature = "coverage", feature = "tdx", target_os = "none"))]
#[no_mangle]
static __llvm_profile_runtime: u32 = 0;

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::TryInto;
use core::ffi::c_void;
use core::mem::size_of;
use serde::{Deserialize, Serialize};
use td_layout::memslice;
use td_payload::hob::get_hob;
use td_shim::e820::{self, E820Entry, E820Type};
use td_shim::TD_E820_TABLE_HOB_GUID;
use td_uefi_pi::hob;
use zerocopy::{AsBytes, FromBytes};

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMapConfig {
    pub size: String,
}

impl MemoryMapConfig {
    pub fn get_size(&self) -> Option<u64> {
        let end = self.size.len();
        if self.size.ends_with("M") {
            let mbytes = u64::from_str_radix(&self.size[0..end - 1], 10).ok()?;
            return Some(mbytes * 0x10_0000);
        } else if self.size.ends_with("G") {
            let gbytes = u64::from_str_radix(&self.size[0..end - 1], 10).ok()?;
            return Some(gbytes * 0x4000_0000);
        }
        None
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMap {
    pub name: String,
    pub expected: MemoryMapConfig,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Test E820 memory map
 */
pub struct TestMemoryMap {
    pub hob_address: usize,
    pub case: MemoryMap,
}

impl TestMemoryMap {
    // Get the E820 table from Payload Handoff Block list
    fn parse_hob(&self, hob_address: usize) -> Option<Vec<E820Entry>> {
        let mut e820: Vec<e820::E820Entry> = Vec::new();

        let hob_list = get_hob().expect("Unable to get payload HOB list");

        let mut next_hob = hob_list;
        if let Some(hob) =
            hob::get_next_extension_guid_hob(next_hob, TD_E820_TABLE_HOB_GUID.as_bytes())
        {
            let table = hob::get_guid_data(hob).expect("Failed to get data from ACPI GUID HOB");

            let mut offset = 0;
            while offset < table.len() && offset + size_of::<E820Entry>() <= table.len() {
                let entry = E820Entry::read_from(&table[offset..offset + size_of::<E820Entry>()])?;
                // save it to tables
                e820.push(entry);
                offset += size_of::<E820Entry>();
            }
        } else {
            log::error!("There's no E820 table can be found in Payload HOB\n");
            return None;
        }

        Some(e820)
    }

    // Verify the following checkpoints:
    // - Entry type parsed from memory map table
    // - Total memory size and memory top limitation
    // - The address should be incremented
    fn verify_memory_map(&self, e820: Vec<E820Entry>) -> TestResult {
        let mut top = 0;
        let mut total = 0;
        let max_gpa = 1 << 51; //tdx::td_shared_page_mask();
        for entry in e820 {
            let entry_end = entry.addr + entry.size;
            if entry.r#type < E820Type::Memory as u32
                || entry.r#type > E820Type::Unaccepted as u32
                || entry.addr < top
                || entry_end > max_gpa
            {
                log::error!("Invalid E820 entry: {:x?}\n", entry);
                return TestResult::Fail;
            }

            total += entry.size;
            top = entry_end;
        }

        if let Some(memory_size) = self.case.expected.get_size() {
            if total != memory_size {
                log::error!(
                    "Mismatch memory size: {:x}, expected: {:x}\n",
                    total,
                    memory_size
                );
                TestResult::Fail
            } else {
                TestResult::Pass
            }
        } else {
            log::error!("Invaild memory size provided\n");
            TestResult::Fail
        }
    }
}

/**
 * Implement the TestCase trait for ACPI
 */
impl TestCase for TestMemoryMap {
    /**
     * set up the Test case of Tdinfo
     */
    fn setup(&mut self) {
        self.case.result = TestResult::Fail;
    }

    /**
     * run the test case
     */
    fn run(&mut self) {
        if let Some(e820_table) = self.parse_hob(self.hob_address) {
            self.case.result = self.verify_memory_map(e820_table);
        } else {
            self.case.result = TestResult::Fail;
        }
    }

    /**
     * Tear down the test case.
     */
    fn teardown(&mut self) {}

    /**
     * get the name of the test case.
     */
    fn get_name(&mut self) -> String {
        String::from(&self.case.name)
    }

    /**
     * get the result of the test case.
     */
    fn get_result(&mut self) -> TestResult {
        self.case.result
    }
}

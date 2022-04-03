// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use serde::{Deserialize, Serialize};
use td_layout::memslice;
use td_shim::acpi::GenericSdtHeader;
use td_shim::TD_ACPI_TABLE_HOB_GUID;
use td_uefi_pi::hob;
use zerocopy::FromBytes;

#[derive(Debug, Serialize, Deserialize)]
pub struct TdAcpiData {
    pub name: String,
    pub signature: [u8; 4],
    pub valid: u8,
    pub exist: u8,
}

impl Default for TdAcpiData {
    fn default() -> TdAcpiData {
        TdAcpiData {
            name: String::default(),
            signature: [0, 0, 0, 0],
            valid: 0,
            exist: 0,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TdAcpiList {
    pub num: u32,
    pub tables: [TdAcpiData; 2],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TdAcpi {
    pub name: String,
    pub expected: TdAcpiList,
    pub result: TestResult,
    pub run: bool,
}
/**
 * Test ACPI
 */
// #[derive(Debug, Serialize, Deserialize)]
pub struct TestTdAcpi {
    pub hob_address: usize,
    pub td_acpi: TdAcpi,
}

impl TestTdAcpi {
    fn calculate_checksum(&self, data: &[u8]) -> u8 {
        (255 - data.iter().fold(0u8, |acc, x| acc.wrapping_add(*x))).wrapping_add(1)
    }

    fn parse_hob(&self, hob_address: usize) -> Vec<TdAcpiData> {
        let mut tables: Vec<TdAcpiData> = Vec::new();

        // Parse Hob to populate td_acpi_list
        let hob_buffer = unsafe {
            memslice::get_dynamic_mem_slice_mut(memslice::SliceType::PayloadHob, hob_address)
        };

        let hob_size = hob::get_hob_total_size(hob_buffer).unwrap();
        let hob_list = &hob_buffer[..hob_size];

        let mut next_hob = hob_list;
        while let Some(hob) = hob::get_next_extension_guid_hob(next_hob, TD_ACPI_TABLE_HOB_GUID.as_bytes()) {
            let table = hob::get_guid_data(hob).expect("Failed to get data from ACPI GUID HOB");
            let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()])
                .expect("Faile to read table header from ACPI GUID HOB");

            let mut tbl = TdAcpiData {
                name: String::from_utf8(header.signature.to_ascii_uppercase()).unwrap(),
                signature: header.signature,
                valid: 1,
                exist: 1,
            };

            // save it to tables
            tables.push(tbl);

            // Then we go to next hob
            next_hob = hob::seek_to_next_hob(hob).unwrap();
        }

        return tables;
    }

    fn verify_tables(&self, acpi_tables: Vec<TdAcpiData>) -> TestResult {
        if acpi_tables.len() == 0 {
            log::info!("Not find ACPI tables in Hob\n");
            return TestResult::Fail;
        }

        let mut cnt: usize = 0;
        while cnt < self.td_acpi.expected.num as usize {
            let expected_signature = self.td_acpi.expected.tables[cnt].signature;

            let index = acpi_tables
                .iter()
                .position(|r| r.signature == expected_signature);
            // if the ACPI is not found
            if index.is_none() {
                log::info!(
                    "ACPI {} is not found.",
                    String::from_utf8_lossy(&expected_signature)
                );
                return TestResult::Fail;
            }

            // valid?
            let idx = index.unwrap();

            if acpi_tables[idx].valid == 0 {
                // This table is not valid
                log::info!(
                    "ACPI {} is not valid.",
                    String::from_utf8_lossy(&expected_signature)
                );
                return TestResult::Fail;
            }

            cnt += 1;
        }

        return TestResult::Pass;
    }
}

/**
 * Implement the TestCase trait for ACPI
 */
impl TestCase for TestTdAcpi {
    /**
     * set up the Test case of Tdinfo
     */
    fn setup(&mut self) {
        self.td_acpi.result = TestResult::Fail;
    }

    /**
     * run the test case
     */
    fn run(&mut self) {
        let acpi_tables = self.parse_hob(self.hob_address);

        self.td_acpi.result = self.verify_tables(acpi_tables);
    }

    /**
     * Tear down the test case.
     */
    fn teardown(&mut self) {}

    /**
     * get the name of the test case.
     */
    fn get_name(&mut self) -> String {
        String::from(&self.td_acpi.name)
    }

    /**
     * get the result of the test case.
     */
    fn get_result(&mut self) -> TestResult {
        self.td_acpi.result
    }
}

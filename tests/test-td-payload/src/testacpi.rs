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
use td_payload::hob::get_hob;
use td_shim::acpi::GenericSdtHeader;
use td_shim::TD_ACPI_TABLE_HOB_GUID;
use td_uefi_pi::hob;
use zerocopy::{AsBytes, FromBytes};

#[derive(Debug, Serialize, Deserialize)]
pub struct TdAcpiData {
    pub name: String,
    pub signature: [u8; 4],
}

impl Default for TdAcpiData {
    fn default() -> TdAcpiData {
        TdAcpiData {
            name: String::default(),
            signature: [0, 0, 0, 0],
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

    fn parse_hob(&self, hob_address: usize) -> Vec<GenericSdtHeader> {
        let mut tables: Vec<GenericSdtHeader> = Vec::new();

        // Parse Hob to populate td_acpi_list
        let hob_list = get_hob().expect("Unable to get payload HOB list");

        let mut next_hob = hob_list;
        while let Some(hob) =
            hob::get_next_extension_guid_hob(next_hob, TD_ACPI_TABLE_HOB_GUID.as_bytes())
        {
            let table = hob::get_guid_data(hob).expect("Failed to get data from ACPI GUID HOB\n");
            let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()])
                .expect("Faile to read table header from ACPI GUID HOB\n");

            // Check checksum
            if self.calculate_checksum(table) != 0 {
                log::info!(
                    "ACPI checksum {} is not correct\n",
                    String::from_utf8_lossy(&header.signature)
                );
                return tables;
            }
            // save it to tables
            tables.push(header);

            // Then we go to next hob
            next_hob = hob::seek_to_next_hob(hob).unwrap();
        }

        return tables;
    }

    fn verify_tables(&self, acpi_tables: Vec<GenericSdtHeader>) -> TestResult {
        if acpi_tables.len() == 0 {
            log::info!("Not find ACPI tables in Hob or no ACPI tables found with valid checksum\n");
            return TestResult::Fail;
        }

        if acpi_tables.len() != self.td_acpi.expected.num as usize {
            log::info!(
                "Not find all ACPI tables in Hob, expected {}\n",
                self.td_acpi.expected.num as usize
            );
            return TestResult::Fail;
        }

        let mut cnt: usize = 0;
        while cnt < acpi_tables.len() {
            let expected_signature = self.td_acpi.expected.tables[cnt].signature;
            let index = acpi_tables
                .iter()
                .position(|r| r.signature == expected_signature);
            // if the ACPI is not found
            if index.is_none() {
                log::info!(
                    "ACPI {} is not found.\n",
                    String::from_utf8_lossy(&expected_signature)
                );
                return TestResult::Fail;
            }

            let idx = index.unwrap();

            if acpi_tables[idx].revision != 1
                || acpi_tables[idx].oem_id != *b"INTEL "
                || acpi_tables[idx].oem_table_id != u64::from_le_bytes(*b"SHIM    ")
                || acpi_tables[idx].creator_id != u32::from_le_bytes(*b"SHIM")
            {
                log::info!(
                    "Expected revision: 1          Actual revision: {:?}\n",
                    acpi_tables[idx].revision
                );
                log::info!(
                    "Expected oem_id: 'Intel'      Actual oem_id: {:?}\n",
                    String::from_utf8_lossy(&acpi_tables[idx].oem_id)
                );
                log::info!(
                    "Expected oem_table_id: 'SHIM' Actual oem_table_id: {:?}\n",
                    String::from_utf8_lossy(&u64::to_le_bytes(acpi_tables[idx].oem_table_id))
                );
                log::info!(
                    "Expected creator_id: 'SHIM'   Actual creator_id: {:?}\n",
                    String::from_utf8_lossy(&u32::to_le_bytes(acpi_tables[idx].creator_id))
                );

                log::info!(
                    "ACPI {} is not valid.\n",
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

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::{string::String, vec::Vec};
use core::{convert::TryInto, ffi::c_void, mem::size_of};
use ring::digest;
use scroll::Pread;
use td_layout::memslice;
use td_shim::acpi::GenericSdtHeader;
use td_shim::event_log::{TcgPcrEvent2Header, TdEventDumper, Tdel, PCR_EVENT_HEADER_SIZE};
use td_shim::TD_ACPI_TABLE_HOB_GUID;
use td_uefi_pi::hob;
use tdx_tdcall::tdreport;
use zerocopy::{AsBytes, FromBytes};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TdTrustedBoot {
    pub name: String,
    pub input: Vec<u8>,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Test TdTrustedBoot
 */
pub struct TestTdTrustedBoot {
    pub hob_address: usize,
    pub case: TdTrustedBoot,
}

impl TestTdTrustedBoot {
    fn get_rtmr0_from_tdreport(&mut self) -> [u8; 48] {
        let tdx_report = tdreport::tdcall_report(
            &self.case.input[0..tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE]
                .try_into()
                .unwrap(),
        );
        tdx_report.td_info.rtmr0
    }

    fn parse_hob(&self, hob_address: usize) -> Option<Vec<Tdel>> {
        let mut tdel: Vec<Tdel> = Vec::new();

        // Parse Hob to populate td_acpi_list
        let hob_buffer = unsafe {
            memslice::get_dynamic_mem_slice_mut(memslice::SliceType::PayloadHob, hob_address)
        };

        let hob_size = hob::get_hob_total_size(hob_buffer).unwrap();
        let hob_list = &hob_buffer[..hob_size];

        let mut next_hob = hob_list;
        while let Some(hob) =
            hob::get_next_extension_guid_hob(next_hob, TD_ACPI_TABLE_HOB_GUID.as_bytes())
        {
            let table = hob::get_guid_data(hob).expect("Failed to get data from ACPI GUID HOB");
            let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()])
                .expect("Failed to read table header from ACPI GUID HOB");

            // save it to headers
            if &header.signature == b"TDEL" {
                let tdel_table = Tdel::read_from(&table[..size_of::<Tdel>()])
                    .expect("Failed to read TDEL table header from ACPI GUID HOB");
                tdel.push(tdel_table);
            }

            // Then we go to next hob
            next_hob = hob::seek_to_next_hob(hob).unwrap();
        }

        return Some(tdel);
    }

    fn get_rtmr0_from_tdeltable(&self, tables: Vec<Tdel>) -> [u8; 48] {
        let tdel_table = &tables[0];
        let eventlog_base = tdel_table.lasa;
        let eventlog_len = tdel_table.laml as usize;
        let eventlog =
            unsafe { core::slice::from_raw_parts(eventlog_base as *const u8, eventlog_len) };

        let mut rtmr0: [u8; 96] = [0; 96];

        let mut offset = 0;
        while offset < eventlog_len {
            if let Some(td_event_header) = self.read_header(eventlog, offset) {
                offset += PCR_EVENT_HEADER_SIZE;
                let td_event_size = td_event_header.event_size as usize;
                if td_event_size + offset <= eventlog_len {
                    let td_event_data = &eventlog[offset..offset + td_event_size];
                    let mr_index = match td_event_header.pcr_index {
                        0 => 0xFF,
                        1 | 7 => 0,
                        2..=6 => 1,
                        8..=15 => 2,
                        _ => {
                            log::info!("invalid pcr_index 0x{:x}\n", td_event_header.pcr_index);
                            0xFF
                        }
                    };
                    if mr_index == 0 {
                        rtmr0[48..]
                            .copy_from_slice(&td_event_header.digest.digests[0].digest.sha384);
                        let hash_value = digest::digest(&digest::SHA384, &rtmr0);
                        rtmr0[0..48].copy_from_slice(hash_value.as_ref());
                    }
                }
                offset = offset.saturating_add(td_event_size);
                if td_event_size == 0 {
                    break;
                }
            }
        }
        rtmr0[0..48].try_into().unwrap()
    }

    fn read_header(&self, area: &[u8], offset: usize) -> Option<TcgPcrEvent2Header> {
        if let Ok(v) = area.pread::<TcgPcrEvent2Header>(offset) {
            Some(v)
        } else {
            None
        }
    }
}

/**
 * Implement the TestCase trait for TdTrustedBoot
 */
impl TestCase for TestTdTrustedBoot {
    /**
     * set up the Test case of TdTrustedBoot
     */
    fn setup(&mut self) {
        self.case.result = TestResult::Fail;
    }

    /**
     * run the test case
     */
    fn run(&mut self) {
        // Get rtmr0 value from tdreport
        let rtmr0_tdreport = self.get_rtmr0_from_tdreport();
        log::info!("tdreport rtmr0: {:?}\n", rtmr0_tdreport);

        // Get rtmr0 value from acpi table
        let mut rtmr0_eventlog: [u8; 48] = [0; 48];

        if let Some(tdel_table) = self.parse_hob(self.hob_address) {
            if tdel_table.len() == 0 {
                log::info!("No TDEL table found\n");
                return;
            } else {
                rtmr0_eventlog
                    .copy_from_slice(self.get_rtmr0_from_tdeltable(tdel_table).as_bytes());
                log::info!("acpitable rtmr0: {:?}\n", rtmr0_eventlog);
            }
        } else {
            log::info!("Parse Hob fail\n");
            return;
        };

        // Compare rtmr0 values from tdreport and acpi table
        if rtmr0_tdreport != rtmr0_eventlog {
            log::info!("rtmr0 value from tdreport is not equal with the value from acpi table\n");
            return;
        }

        self.case.result = TestResult::Pass;
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

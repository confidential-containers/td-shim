// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::{string::String, vec::Vec};
use cc_measurement::log::CcEventLogReader;
use core::{convert::TryInto, ffi::c_void, mem::size_of};
use ring::digest;
use scroll::Pread;
use td_payload::hob::get_hob;
use td_shim::acpi::{Ccel, GenericSdtHeader};
use td_shim::event_log::CCEL_CC_TYPE_TDX;
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

#[derive(Debug)]
pub struct Rtmr {
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

impl TestTdTrustedBoot {
    fn get_rtmr_from_tdreport(&mut self) -> Rtmr {
        let tdx_report = tdreport::tdcall_report(
            &self.case.input[0..tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE]
                .try_into()
                .unwrap(),
        )
        .expect("Fail to get td report");
        let mr = Rtmr {
            rtmr0: tdx_report.td_info.rtmr0,
            rtmr1: tdx_report.td_info.rtmr1,
            rtmr2: tdx_report.td_info.rtmr2,
            rtmr3: tdx_report.td_info.rtmr3,
        };
        mr
    }

    fn parse_hob(&self, hob_address: usize) -> Option<Ccel> {
        let mut ccel = None;

        // Parse Hob to populate td_acpi_list
        let hob_list = get_hob().expect("Unable to get payload HOB list");

        let mut next_hob = hob_list;
        while let Some(hob) =
            hob::get_next_extension_guid_hob(next_hob, TD_ACPI_TABLE_HOB_GUID.as_bytes())
        {
            let table = hob::get_guid_data(hob).expect("Failed to get data from ACPI GUID HOB");
            let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()])
                .expect("Failed to read table header from ACPI GUID HOB");

            // save it to headers
            if &header.signature == b"CCEL" {
                ccel = Ccel::read_from(&table[..size_of::<Ccel>()]);
            }

            // Then we go to next hob
            next_hob = hob::seek_to_next_hob(hob).unwrap();
        }

        return ccel;
    }

    fn get_rtmr_from_cceltable(&self, ccel_table: Ccel) -> Option<Rtmr> {
        let eventlog_base = ccel_table.lasa;
        let eventlog_len = ccel_table.laml as usize;
        let eventlog =
            unsafe { core::slice::from_raw_parts(eventlog_base as *const u8, eventlog_len) };

        let mut rtmr0: [u8; 96] = [0; 96];
        let mut rtmr1: [u8; 96] = [0; 96];
        let mut rtmr2: [u8; 96] = [0; 96];
        let mut rtmr3: [u8; 96] = [0; 96];

        let mut offset = 0;

        let event_log = CcEventLogReader::new(eventlog)?;

        for (event_header, event_data) in event_log.cc_events {
            let rtmr_index = match event_header.mr_index {
                0 => 0xFF,
                1 | 2 | 3 | 4 => event_header.mr_index - 1,
                e => {
                    log::info!("invalid pcr_index 0x{:x}\n", e);
                    0xFF
                }
            };
            if rtmr_index == 0 {
                rtmr0[48..].copy_from_slice(&event_header.digest.digests[0].digest.sha384);
                let hash_value = digest::digest(&digest::SHA384, &rtmr0);
                rtmr0[0..48].copy_from_slice(hash_value.as_ref());
            } else if rtmr_index == 1 {
                rtmr1[48..].copy_from_slice(&event_header.digest.digests[0].digest.sha384);
                let hash_value = digest::digest(&digest::SHA384, &rtmr1);
                rtmr1[0..48].copy_from_slice(hash_value.as_ref());
            } else if rtmr_index == 2 {
                rtmr2[48..].copy_from_slice(&event_header.digest.digests[0].digest.sha384);
                let hash_value = digest::digest(&digest::SHA384, &rtmr2);
                rtmr2[0..48].copy_from_slice(hash_value.as_ref());
            } else if rtmr_index == 3 {
                rtmr3[48..].copy_from_slice(&event_header.digest.digests[0].digest.sha384);
                let hash_value = digest::digest(&digest::SHA384, &rtmr3);
                rtmr3[0..48].copy_from_slice(hash_value.as_ref());
            }
        }

        let mr = Rtmr {
            rtmr0: rtmr0[0..48].try_into().unwrap(),
            rtmr1: rtmr1[0..48].try_into().unwrap(),
            rtmr2: rtmr2[0..48].try_into().unwrap(),
            rtmr3: rtmr3[0..48].try_into().unwrap(),
        };
        Some(mr)
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
        // Get rtmr values from tdreport
        let rtmr_tdreport = self.get_rtmr_from_tdreport();
        log::info!("tdreport rtmr: {:?}\n", rtmr_tdreport);

        // Get rtmr values from acpi table
        if let Some(ccel_table) = self.parse_hob(self.hob_address) {
            if ccel_table.cc_type != CCEL_CC_TYPE_TDX {
                log::info!(
                    "CC type should be 2(TDX), but found {:x}\n",
                    ccel_table.cc_type
                );
                return;
            }
            let rtmr_eventlog = self.get_rtmr_from_cceltable(ccel_table).unwrap();
            log::info!("acpitable rtmr: {:?}\n", rtmr_eventlog);

            // Compare rtmr values from tdreport and acpi table
            if rtmr_tdreport.rtmr0 != rtmr_eventlog.rtmr0
                || rtmr_tdreport.rtmr1 != rtmr_eventlog.rtmr1
                || rtmr_tdreport.rtmr2 != rtmr_eventlog.rtmr2
                || rtmr_tdreport.rtmr3 != rtmr_eventlog.rtmr3
            {
                log::info!(
                    "rtmr values from tdreport is not equal with the values from acpi table\n"
                );
                return;
            }
        } else {
            log::info!("Fail to parse CCEL from Hob\n");
            return;
        };

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

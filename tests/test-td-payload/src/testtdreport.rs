// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::{string::String, vec::Vec};
use core::{convert::TryInto, ffi::c_void};
use tdx_tdcall::tdreport::{self, ReportMac, ReportType};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TdxReportRetInfo {
    pub r#type: u8,
    pub subtype: u8,
    pub version: u8,
}

/**
 * Test Td Report
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct Tdreport {
    pub name: String,
    pub input: Vec<u8>,
    pub expected: TdxReportRetInfo,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Implement the TestCase trait for Tdreport
 */
impl TestCase for Tdreport {
    /**
     * set up the Test case of Tdreport
     */
    fn setup(&mut self) {
        self.result = TestResult::Fail;
    }
    /**
     * run the test case
     */
    fn run(&mut self) {
        let mut tdx_report = tdreport::tdcall_report(
            &self.input[0..tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE]
                .try_into()
                .unwrap(),
        )
        .expect("Fail to get td report");
        log::info!("{}", tdx_report);

        if (self.expected.r#type != tdx_report.report_mac.report_type.r#type) {
            log::info!(
                "Check Reporttype type fail - Expected {:?}: Actual {:?}\n",
                self.expected.r#type,
                tdx_report.report_mac.report_type.r#type
            );
            return;
        } else {
            log::info!(
                "Reporttype type - {:?}\n",
                tdx_report.report_mac.report_type.r#type
            );
        }

        if (self.expected.subtype != tdx_report.report_mac.report_type.subtype) {
            log::info!(
                "Check Reporttype subtype fail - Expected {:?}: Actual {:?}\n",
                self.expected.subtype,
                tdx_report.report_mac.report_type.subtype
            );
            return;
        } else {
            log::info!(
                "Reporttype subtype - {:?}\n",
                tdx_report.report_mac.report_type.subtype
            );
        }

        if (self.expected.version != tdx_report.report_mac.report_type.version) {
            log::info!(
                "Check Reporttype version fail - Expected {:?}: Actual {:?}\n",
                self.expected.version,
                tdx_report.report_mac.report_type.version
            );
            return;
        } else {
            log::info!(
                "Reporttype version - {:?}\n",
                tdx_report.report_mac.report_type.version
            );
        }

        // Verify the report
        if let Err(e) =
            tdreport::tdcall_verify_report(&tdx_report.as_bytes()[..size_of::<ReportMac>()])
        {
            log::info!(
                "TDReport verification failed - completion status code: {:x?} \n",
                e
            );
            return;
        }

        // // Corrupt the report MAC structure and expect tdcall_verify_report to return an error
        tdx_report.as_bytes_mut()[..size_of::<ReportType>()].copy_from_slice(&[0x81, 1, 0, 0]);
        if let Ok(_) =
            tdreport::tdcall_verify_report(&tdx_report.as_bytes()[..size_of::<ReportMac>()])
        {
            log::info!("TDReport verification failed - expected error not returned\n");
            return;
        }

        self.result = TestResult::Pass;
    }

    /**
     * Tear down the test case.
     */
    fn teardown(&mut self) {}

    /**
     * get the name of the test case.
     */
    fn get_name(&mut self) -> String {
        String::from(&self.name)
    }

    /**
     * get the result of the test case.
     */
    fn get_result(&mut self) -> TestResult {
        self.result
    }
}

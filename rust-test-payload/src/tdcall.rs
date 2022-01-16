// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::String;
use core::ffi::c_void;
use tdx_tdcall::tdreport;
use tdx_tdcall::tdx;

/**
 * Test Tdcall
 */
pub struct Tdcall {
    pub name: String,
    pub hob: *const c_void,
    pub result: TestResult,
}

/**
 * Implement the TestCase trait for Tdcall
 */
impl TestCase for Tdcall {
    /**
     * set up the Test case of Tdcall
     */
    fn setup(&mut self) {
        self.result = TestResult::Error;
    }

    /**
     * run the test case
     */
    fn run(&mut self) {
        log::info!("1. TDCALL: get td info\n");
        let mut td_info = tdx::TdInfoReturnData {
            gpaw: 0,
            attributes: 0,
            max_vcpus: 0,
            num_vcpus: 0,
            rsvd: [0; 3],
        };
        tdx::tdcall_get_td_info(&mut td_info);
        log::info!("attributes - {:?}\n", td_info.attributes);
        log::info!("max_vcpus - {:?}\n", td_info.max_vcpus);
        log::info!("num_vcpus - {:?}\n", td_info.num_vcpus);
        log::info!("rsvd - {:?}\n", td_info.rsvd);

        log::info!("2. TDCALL:report\n");
        let addtional_data: [u8; 64] = [0; 64];
        let tdx_report = tdreport::tdcall_report(&addtional_data);
        log::info!("{}", tdx_report);

        self.result = TestResult::Done;
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

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::String;
use core::ffi::c_void;
use tdx_tdcall::tdx;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TdInfoRetData {
    pub gpaw: u64,
    pub attributes: u64,
    pub max_vcpus: u32,
    pub num_vcpus: u32,
    pub rsvd: [u64; 3],
}

/**
 * Test Tdinfo
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct Tdinfo {
    pub name: String,
    pub expected: TdInfoRetData,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Implement the TestCase trait for Tdinfo
 */
impl TestCase for Tdinfo {
    /**
     * set up the Test case of Tdinfo
     */
    fn setup(&mut self) {
        self.result = TestResult::Pass;
    }

    /**
     * run the test case
     */
    fn run(&mut self) {
        let mut td_info = tdx::TdInfoReturnData {
            gpaw: 0,
            attributes: 0,
            max_vcpus: 0,
            num_vcpus: 0,
            rsvd: [0; 3],
        };
        tdx::tdcall_get_td_info(&mut td_info);

        if (self.expected.gpaw != td_info.gpaw) {
            self.result = TestResult::Fail;
            log::info!(
                "Check gpaw fail - Expected {:?}: Actual {:?}\n",
                self.expected.gpaw,
                td_info.gpaw
            );
            return;
        } else {
            log::info!("gpaw - {:?}\n", td_info.gpaw);
        }

        if (self.expected.max_vcpus != td_info.max_vcpus) {
            self.result = TestResult::Fail;
            log::info!(
                "Check max_vcpus fail - Expected {:?}: Actual {:?}\n",
                self.expected.max_vcpus,
                td_info.max_vcpus
            );
            return;
        } else {
            log::info!("max_vcpus - {:?}\n", td_info.max_vcpus);
        }

        if (self.expected.num_vcpus != td_info.num_vcpus) {
            self.result = TestResult::Fail;
            log::info!(
                "Check num_vcpus fail - Expected {:?}: Actual {:?}\n",
                self.expected.num_vcpus,
                td_info.num_vcpus
            );
            return;
        } else {
            log::info!("num_vcpus - {:?}\n", td_info.num_vcpus);
        }

        if (self.expected.max_vcpus != td_info.num_vcpus) {
            self.result = TestResult::Fail;
            log::info!(
                "max_vcpus should be equal num_vcpus fail - max_vcpus {:?}: num_vcpus {:?}\n",
                self.expected.max_vcpus,
                td_info.num_vcpus
            );
            return;
        }

        if (self.expected.rsvd != td_info.rsvd) {
            self.result = TestResult::Fail;
            log::info!(
                "Check rsvd fail - Expected {:?}: Actual {:?}\n",
                self.expected.rsvd,
                td_info.rsvd
            );
            return;
        } else {
            log::info!("rsvd - {:?}\n", td_info.rsvd);
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
        String::from(&self.name)
    }

    /**
     * get the result of the test case.
     */
    fn get_result(&mut self) -> TestResult {
        self.result
    }
}

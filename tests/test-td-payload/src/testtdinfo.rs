// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::String;
use core::ffi::c_void;
use tdx_tdcall::tdcall;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TdInfoRetData {
    pub gpaw: u64,
    pub attributes: u64,
    pub max_vcpus: u32,
    pub num_vcpus: u32,
    pub vcpu_index: u32,
    pub rsvd: [u32; 5],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TdInfoExpectedData {
    pub attributes: u64,
    pub max_vcpus: u32,
    pub num_vcpus: u32,
    pub vcpu_index: u32,
    pub rsvd: [u32; 5],
}

/**
 * Test Tdinfo
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct Tdinfo {
    pub name: String,
    pub expected: TdInfoExpectedData,
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
        self.result = TestResult::Fail;
    }

    /**
     * run the test case
     */
    fn run(&mut self) {
        let mut td_info = tdcall::get_td_info().expect("Failt to get td info");
        // Only GPAW values 48 and 52 are possible.
        if (td_info.gpaw != 52) && (td_info.gpaw != 48) {
            log::info!(
                "Check gpaw fail - The value should be 48 or 52, Actual {:?}\n",
                td_info.gpaw
            );
            return;
        } else {
            log::info!("gpaw - {:?}\n", td_info.gpaw);
        }

        if (self.expected.max_vcpus != td_info.max_vcpus) {
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
            log::info!(
                "max_vcpus should be equal num_vcpus fail - max_vcpus {:?}: num_vcpus {:?}\n",
                self.expected.max_vcpus,
                td_info.num_vcpus
            );
            return;
        }

        if (self.expected.vcpu_index != td_info.vcpu_index) {
            log::info!(
                "Check vcpu_index fail - Expected {:?}: Actual {:?}\n",
                self.expected.vcpu_index,
                td_info.vcpu_index
            );
            return;
        } else {
            log::info!("vcpu_index - {:?}\n", td_info.vcpu_index);
        }

        if (self.expected.rsvd != td_info.rsvd) {
            log::info!(
                "Check rsvd fail - Expected {:?}: Actual {:?}\n",
                self.expected.rsvd,
                td_info.rsvd
            );
            return;
        } else {
            log::info!("rsvd - {:?}\n", td_info.rsvd);
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

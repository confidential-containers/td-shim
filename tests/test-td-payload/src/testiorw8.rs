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

/**
 * Test tdvmcall io read/write 8
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct Tdiorw8 {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Implement the TestCase trait for Tdiorw8
 */
impl TestCase for Tdiorw8 {
    /**
     * set up the Test case of Tdiorw8
     */
    fn setup(&mut self) {
        self.result = TestResult::Fail;
    }

    /**
     * run the test case
     * io read Century of RTC
     */
    fn run(&mut self) {
        tdx::tdvmcall::io_write_8(0x70, 0x32);

        let read1 = tdx::tdvmcall::io_read_8(0x71);
        log::info!("First time read {}\n", read1);

        tdx::tdvmcall::io_write_8(0x71, read1 + 1);

        let read2 = tdx::tdvmcall::io_read_8(0x71);
        log::info!("Second time read {}\n", read2);

        if (read1 + 1 != read2) {
            log::info!(
                "Second time value is not equal with the first time value + 1 - Expected {:?}: Actual {:?}\n",
                read1 + 1,
                read2
            );
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

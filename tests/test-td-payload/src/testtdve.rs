// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::String;

use serde::{Deserialize, Serialize};

/**
 * Test #VE
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct TdVE {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Implement the TestCase trait for TdVE
 */
impl TestCase for TdVE {
    /**
     * set up the Test case of TdVE
     */
    fn setup(&mut self) {
        self.result = TestResult::Fail;
    }

    /**
     * run the test case
     * io read Century of RTC
     */
    fn run(&mut self) {
        unsafe { x86::io::outb(0x70, 0x32) };

        let century = unsafe { x86::io::inb(0x71) };
        log::info!("Current century is {}\n", century);

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

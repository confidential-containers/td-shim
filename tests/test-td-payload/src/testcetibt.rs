// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::String;

use serde::{Deserialize, Serialize};

/**
 * Test functionality of CET indirect branch tracking of `td-payload`
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct TestCetIbt {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Implement the TestCase trait for TestCetIbt
 */
impl TestCase for TestCetIbt {
    /**
     * set up the Test case of TestCetIbt
     */
    fn setup(&mut self) {
        self.result = TestResult::Fail;
    }

    /**
     * run the test case
     * unable to resume execution after triggering control flow exception
     * this function will never return
     */
    fn run(&mut self) {
        unsafe { test_without_endbr() }
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

extern "sysv64" {
    fn test_without_endbr();
}

core::arch::global_asm!(
    "
    .global test_without_endbr
    test_without_endbr:
    ret",
);

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::String;

use serde::{Deserialize, Serialize};

/**
 * Test functionality of CET shadow stack of `td-payload`
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct TestCetShstk {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Implement the TestCase trait for TestCetShstk
 */
impl TestCase for TestCetShstk {
    /**
     * set up the Test case of TestCetShstk
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
        // Recursive call, ending with a page fault exception
        unsafe {
            tamper_return_address();
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

extern "sysv64" {
    fn tamper_return_address();
}

core::arch::global_asm!(
    "
    .global tamper_return_address
    tamper_return_address:
    mov rax, rsp
    mov dword ptr [rax], 0xfefefefe
    ret",
);

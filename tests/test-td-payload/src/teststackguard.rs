// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::String;

use serde::{Deserialize, Serialize};

/**
 * Test functionality of stack guard (guard page) of `td-payload`
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct TestStackGuard {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

/**
 * Implement the TestCase trait for TestStackGuard
 */
impl TestCase for TestStackGuard {
    /**
     * set up the Test case of TestStackGuard
     */
    fn setup(&mut self) {
        self.result = TestResult::Fail;
    }

    /**
     * run the test case
     * unable to resume execution after triggering page fault exception
     * this function will never return
     */
    fn run(&mut self) {
        // Recursive call, ending with a page fault exception
        unsafe {
            recursive();
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

extern "C" {
    fn recursive();
}

core::arch::global_asm!(
    "
    .global recursive
    recursive:
    call recursive
    ret",
);

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use td_payload::print;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum TestResult {
    Pass,
    Fail,
    None,
}

pub trait TestCase {
    fn setup(&mut self);
    fn run(&mut self);
    fn teardown(&mut self);
    fn get_name(&mut self) -> String;
    fn get_result(&mut self) -> TestResult;
}

pub struct TestSuite {
    pub testsuite: Vec<Box<dyn TestCase>>,
    pub passed_cases: u32,
    pub failed_cases: u32,
}

impl TestSuite {
    pub fn run(&mut self) {
        for tc in self.testsuite.iter_mut() {
            print!("[Test: {}]\n", String::from(tc.get_name()));
            tc.setup();
            tc.run();
            tc.teardown();

            let res = tc.get_result();
            match res {
                TestResult::Pass => {
                    self.passed_cases += 1;
                    print!("[Test: {0}] - Pass\n", tc.get_name());
                }
                TestResult::Fail => {
                    self.failed_cases += 1;
                    print!("[Test: {0}] - Fail\n", tc.get_name());
                }
                TestResult::None => {
                    print!("[Test: {0}] - Skip\n", tc.get_name());
                }
            }

            print!("---------------------------------------------\n")
        }
    }
}

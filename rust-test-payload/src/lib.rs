// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Copy, Clone)]
pub enum TestResult {
    Done,
    Error,
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
    pub done_cases: u32,
    pub failed_cases: u32,
}

impl TestSuite {
    pub fn run(&mut self) {
        for tc in self.testsuite.iter_mut() {
            log::info!("[Test: {}]\n", String::from(tc.get_name()));
            tc.setup();
            tc.run();
            tc.teardown();

            let res = tc.get_result();
            match res {
                TestResult::Done => {
                    self.done_cases += 1;
                    log::info!("[Test: {0}] - Done\n", tc.get_name());
                }
                TestResult::Error => {
                    self.failed_cases += 1;
                    log::info!("[Test: {0}] - Error\n", tc.get_name());
                }
            }

            log::info!("---------------------------------------------\n")
        }
    }
}

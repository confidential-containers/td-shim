// Copyright (c) 2022 Intel Corporation
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
 * Test tdvmcall read/write MSR
 */
#[derive(Debug, Serialize, Deserialize)]
pub struct Tdmsrrw {
    pub name: String,
    pub result: TestResult,
    pub run: bool,
}

impl Tdmsrrw {
    fn test(&mut self) -> TestResult {
        const APIC_SVR_MSR: u32 = 0x80f; // APIC Spurious Vector Register MSR address

        // Read the current value of the APIC SVR MSR
        match tdx::tdvmcall::rdmsr(APIC_SVR_MSR) {
            Ok(read1) => {
                // Attempt to write the incremented value back to the APIC SVR MSR
                if tdx::tdvmcall::wrmsr(APIC_SVR_MSR, read1 + 1).is_err() {
                    log::info!("Failed to write MSR 0x{:x}", APIC_SVR_MSR);
                    return TestResult::Fail;
                }

                // Read the value again to verify the write operation
                match tdx::tdvmcall::rdmsr(APIC_SVR_MSR) {
                    Ok(read2) if read1 + 1 == read2 => TestResult::Pass,
                    Ok(read2) => {
                        log::info!(
                            "Mismatch after write: expected {:?}, actual {:?}",
                            read1 + 1,
                            read2
                        );
                        TestResult::Fail
                    }
                    Err(_) => {
                        log::info!("Failed to read MSR 0x{:x}", APIC_SVR_MSR);
                        TestResult::Fail
                    }
                }
            }
            Err(_) => {
                log::info!("Failed to read MSR 0x{:x}", APIC_SVR_MSR);
                TestResult::Fail
            }
        }
    }
}

/**
 * Implement the TestCase trait for Tdmsrrw
 */
impl TestCase for Tdmsrrw {
    /**
     * set up the Test case of Tdmsrrw
     */
    fn setup(&mut self) {
        self.result = TestResult::Fail;
    }

    /**
     * run the test case
     * mmio read/write vsock device
     */
    fn run(&mut self) {
        self.result = self.test();
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

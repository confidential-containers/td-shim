#![no_std]
extern crate alloc;

use crate::lib::{TestCase, TestResult};
use alloc::string::String;
use core::ffi::c_void;
use tdx_tdcall::tdx;

/**
 * Test Tdinfo
 */
pub struct Tdinfo {
  pub name: String,
  pub hob: *const c_void,
  pub result: TestResult
}

/**
 * Implement the TestCase trait for Tdinfo
 */
impl TestCase for Tdinfo {

  /**
   * set up the Test case of Tdinfo
   */
  fn setup(&mut self) {
      self.result = TestResult::Error;
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

    log::info!("gpaw - {:?}\n", td_info.gpaw);
    log::info!("attributes - {:?}\n", td_info.attributes);
    log::info!("max_vcpus - {:?}\n", td_info.max_vcpus);
    log::info!("num_vcpus - {:?}\n", td_info.num_vcpus);
    log::info!("rsvd - {:?}\n", td_info.rsvd);

    self.result = TestResult::Done;
  }

  /**
   * Tear down the test case.
   */
  fn teardown(&mut self) {
  }

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
// Copyright © 2019 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
#![cfg_attr(not(test), no_main)]
#![feature(alloc_error_handler)]
#![allow(unused)]

use core::mem::size_of;

use alloc::vec::Vec;
use scroll::{Pread, Pwrite};
use td_layout::RuntimeMemoryLayout;
use td_payload as _;
use td_payload::println;
use td_shim::e820::{E820Entry, E820Type};
use td_shim::{TD_ACPI_TABLE_HOB_GUID, TD_E820_TABLE_HOB_GUID};
use td_uefi_pi::hob;
use td_uefi_pi::pi;
use zerocopy::FromBytes;

#[macro_use]
extern crate alloc;

mod mp;
#[cfg(feature = "benches")]
mod stack;

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main() -> ! {
    use td_payload::hob::get_hob;

    println!(
        "Starting td-payload hob - {:p}",
        get_hob().unwrap().as_ptr()
    );

    #[cfg(feature = "benches")]
    {
        stack::bench_stack(memory_layout);
    }

    #[cfg(feature = "tdx")]
    {
        use tdx_tdcall::tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE;
        //Dump TD Report
        let tdx_report =
            tdx_tdcall::tdreport::tdcall_report(&[0u8; TD_REPORT_ADDITIONAL_DATA_SIZE]);
        println!("{:?}", tdx_report);
    }

    panic!("td-payload: all tests finished and enters dead loop");
}

#[cfg(test)]
fn main() {}

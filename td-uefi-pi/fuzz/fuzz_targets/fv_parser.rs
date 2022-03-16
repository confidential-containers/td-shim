// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
#![no_main]
use libfuzzer_sys::fuzz_target;


use td_uefi_pi::{fv, pi};

fn fuzz_fv_parser(data: &[u8]) {
    let res = fv::get_image_from_fv(data, pi::fv::FV_FILETYPE_DXE_CORE, pi::fv::SECTION_PE32);
    println!("{:?}", res.unwrap_or_default().len());
}

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    fuzz_fv_parser(data);
});

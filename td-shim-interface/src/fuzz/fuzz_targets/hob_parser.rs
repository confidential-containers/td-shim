// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
#![no_main]
use libfuzzer_sys::fuzz_target;

mod fuzzlib;
use fuzzlib::fuzz_hob_parser;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    fuzz_hob_parser(data);
});

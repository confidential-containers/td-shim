// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
#![no_main]

mod fuzzlib;
use fuzzlib::fuzz_elf_loader;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    fuzz_elf_loader(data);
});

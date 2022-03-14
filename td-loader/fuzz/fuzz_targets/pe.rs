// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
#![no_main]
use libfuzzer_sys::fuzz_target;

use td_loader::pe::{is_x86_64_pe, relocate, relocate_pe_mem_with_per_sections, Sections};

pub fn fuzz_pe_loader(data: &[u8]) {
    if is_x86_64_pe(data) {
        let sections = Sections::parse(data, 5 as usize);
        if sections.is_some() {
            let sections = sections.unwrap();
            for section in sections {
                println!("{:?}", section);
            }

            let mut loaded_buffer = vec![0u8; 0x200000];

            relocate(data, loaded_buffer.as_mut_slice(), 0x100000);

            relocate_pe_mem_with_per_sections(data, loaded_buffer.as_mut_slice(), |_| ());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    fuzz_pe_loader(data);
});

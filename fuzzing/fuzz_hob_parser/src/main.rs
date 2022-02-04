// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use uefi_pi::pi::hob;

const HOB_ACPI_TABLE_GUID: [u8; 16] = [
    0x70, 0x58, 0x0c, 0x6a, 0xed, 0xd4, 0xf4, 0x44, 0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0xc, 0x8d,
];

const HOB_KERNEL_INFO_GUID: [u8; 16] = [
    0x12, 0xa4, 0x6f, 0xb9, 0x1f, 0x46, 0xe3, 0x4b, 0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0,
];

fn fuzz_hob_parser(buffer: &[u8]) {
    if hob::get_hob_total_size(buffer).is_some() {
        hob::dump_hob(buffer);
        hob::get_system_memory_size_below_4gb(buffer);
        hob::get_total_memory_top(buffer);
        hob::get_fv(buffer);
        hob::get_next_extension_guid_hob(buffer, &HOB_ACPI_TABLE_GUID);
        hob::get_next_extension_guid_hob(buffer, &HOB_KERNEL_INFO_GUID);
        hob::get_guid_data(buffer);
        hob::get_nex_hob(buffer);
    }
}
fn main() {
    #[cfg(not(feature = "fuzz"))]
    {
        // Command line input seed file location
        let mut args = std::env::args().skip(1);
        if let Some(arg) = args.next() {
            println!("{}", arg);
            let data = std::fs::read(arg).expect("read crash file fail");
            fuzz_hob_parser(data.as_slice());
        } else {
            let crashes_path = "fuzzing/out/fuzz_hob_parser/default/crashes";
            let single_run = || {
                let path = "fuzzing/in/fuzz_hob_parser/hob_buffer";
                let data = std::fs::read(path).expect("read crash file fail");
                fuzz_hob_parser(data.as_slice());
            };
            // Read the crashes folder
            match std::fs::read_dir(crashes_path) {
                Ok(paths) => {
                    // No files in the crashes folder
                    if paths.count() == 0 {
                        single_run();
                        std::fs::remove_dir(crashes_path).unwrap();
                    } else {
                        println!("Run the crashes file in a loop...");
                        for path in std::fs::read_dir(crashes_path).unwrap() {
                            let path = &path.unwrap().path();
                            if path.ends_with("README.txt") {
                                continue;
                            }
                            let data = std::fs::read(path).expect("read crash file fail");
                            fuzz_hob_parser(data.as_slice());
                        }
                    }
                }
                // The crashes folder does not exist, run single_run
                Err(_) => {
                    single_run();
                }
            }
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_hob_parser(data);
    });
}

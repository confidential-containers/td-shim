// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod fuzzlib;
use fuzzlib::fuzz_hob_parser;

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
            let crashes_path = "../crtifacts/afl_hob_parser/default/crashes";
            let single_run = || {
                let path = "../seeds/hob_buffer";
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

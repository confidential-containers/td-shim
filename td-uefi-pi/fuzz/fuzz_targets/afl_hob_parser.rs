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
            let paths = std::path::Path::new(&arg);

            if paths.is_file() {
                let data = std::fs::read(&paths).expect("read crash file fail");
                fuzz_hob_parser(data.as_slice());
            }
            else if paths.is_dir() {
                for path in std::fs::read_dir(paths).unwrap() {
                    let path = &path.unwrap().path();
                    if path.ends_with("README.txt") {
                        continue;
                    }

                    let data = std::fs::read(path).expect("read crash file fail");
                    fuzz_hob_parser(data.as_slice());
                }
            }
            else {
                println!("No valid file path entered");
            }
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_hob_parser(data);
    });
}

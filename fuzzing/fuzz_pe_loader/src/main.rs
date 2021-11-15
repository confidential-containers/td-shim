// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use pe_loader::pe::{is_pe, relocate, relocate_pe_mem_with_per_sections, Sections};

fn fuzz_pe_loader(data: &[u8]) {
    {
        // is pe
        is_pe(data);
        let image_bytes = &mut [0u8; 10][..];
        is_pe(image_bytes);

        let image_bytes = &mut [0u8; 0x55][..];
        is_pe(image_bytes);

        image_bytes[0] = 0x4du8;
        image_bytes[1] = 0x5au8;
        is_pe(image_bytes);

        image_bytes[0x3c] = 0x10;
        image_bytes[0x10] = 0x50;
        image_bytes[0x11] = 0x45;
        image_bytes[0x12] = 0x00;
        image_bytes[0x13] = 0x00;
        is_pe(image_bytes);

        image_bytes[0x3c] = 0xAA;
        is_pe(image_bytes);
    }
    {
        // sections

        let sections = Sections::parse(data, 5 as usize).unwrap();
        for section in sections {
            println!("{:?}", section);
        }
    }
    {
        let mut loaded_buffer = vec![0u8; 0x200000];

        relocate(data, loaded_buffer.as_mut_slice(), 0x100000);

        relocate_pe_mem_with_per_sections(data, loaded_buffer.as_mut_slice(), |_| ());
    }
}

fn main() {
    #[cfg(not(feature = "fuzz"))]
    {
        let mut args = std::env::args().skip(1);
        if let Some(arg) = args.next() {
            println!("{}", arg);
            let data = std::fs::read(arg).expect("read crash file fail");
            fuzz_pe_loader(data.as_slice());
        } else {
            match std::fs::read_dir("fuzzing/out/fuzz_pe_loader/default/crashes") {
                Ok(paths) => {
                    for path in paths {
                        let path = &path.unwrap().path();
                        if path.ends_with("README.txt") {
                            continue;
                        }
                        let data = std::fs::read(path).expect("read crash file fail");
                        fuzz_pe_loader(data.as_slice());
                    }
                }
                Err(_) => {
                    let path = "fuzzing/in/fuzz_pe_loader/rust-tdshim.efi";
                    let data = std::fs::read(path).expect("read crash file fail");
                    fuzz_pe_loader(data.as_slice());
                }
            }
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_pe_loader(data);
    });
}

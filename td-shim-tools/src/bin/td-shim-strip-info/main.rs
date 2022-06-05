// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use argparse::{ArgumentParser, Store, StoreTrue};
use regex::bytes::Regex;
use std::convert::TryInto;
use std::fs;
use std::io::Read;
use std::mem::size_of;
use std::{env, fs::File, path::PathBuf};
use zeroize::Zeroize;

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
const PE_SIG_PTR_OFF: usize = 0x3C;
const NUMBER_OF_SECTIONS_OFF_TO_PE_SIG: usize = 0x6;
const TIMEDATASTAMP_OFF_TO_PE_SIG: usize = 0x8;
const SIZE_OF_OPTIONAL_HEADER_OFF_TO_PE_SIG: usize = 0x14;
const FILE_TYPE_MAGIC_OFF_TO_PE_SIG: usize = 0x18;
const IMAGEBASE_OFF_TO_PE_SIG_PE32_PLUS: usize = 0x30;
const IMAGEBASE_OFF_TO_PE_SIG_PE32: usize = 0x34;
const SECTION_ALIGNMENT_OFF_TO_PE_SIG: usize = 0x38;
const FILE_ALIGNMENT_OFF_TO_PE_SIG: usize = 0x3C;
const NUMBER_OF_RVA_AND_SIZES_OFF_TO_PE_SIG_PE32: usize = 0x74;
const NUMBER_OF_RVA_AND_SIZES_OFF_TO_PE_SIG_PE32_PLUS: usize = 0x84;
const DIRECTORY_ENTRY_START_OFF_TO_PE_SIG_PE32: usize = 0x78;
const DIRECTORY_ENTRY_START_OFF_TO_PE_SIG_PE32_PLUS: usize = 0x88;
const DEBUG_TABLE_OFF_TO_PE_SIG_PE32: usize = 0xA8;
const DEBUG_TABLE_OFF_TO_PE_SIG_PE32_PLUS: usize = 0xB8;

const PE32_MAGIC: u16 = 0x10B;
// const ROM_MAGIC: u16 = 0x107;
const PE32_PLUS_MAGIC: u16 = 0x20B;

// Debug directory
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const DEBUG_TIMEDATESTAMP_OFF_TO_DEBUG_RVA: usize = 0x4;
const DEBUG_TYPE_OFF_TO_DEBUG_RVA: usize = 0xC;
const POINTER_TO_RAW_DATA_OFF_TO_DEBUG_RVA: usize = 0x18;

// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
// CodeView Debug Directory Entry (type 2 IMAGE_DEBUG_TYPE_CODEVIEW)
const GUID_OFF_TO_DEBUG_DATA: usize = 4;

// https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-imagedirectoryentrytodata
const DEBUG_TABLE_INDEX: usize = 6;

#[derive(Debug, Default, Clone, Copy)]
pub struct PESectionTable {
    pub name: u64,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl PESectionTable {
    fn read_bytes(bytes: &[u8]) -> Option<Self> {
        let mut off: usize = 0;
        let name = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let virtual_size = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let virtual_address = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let size_of_raw_data = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let pointer_to_raw_data = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let pointer_to_relocations = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let pointer_to_linenumbers = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        let number_of_relocations = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        let number_of_linenumbers = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        let characteristics = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        Some(PESectionTable {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_linenumbers,
            number_of_relocations,
            number_of_linenumbers,
            characteristics,
        })
    }
}

fn get_entry_fa(off: usize, count: usize, rva: u32, buf: &[u8]) -> u32 {
    for i in 0..count {
        let section_header =
            PESectionTable::read_bytes(&buf[off + i * size_of::<PESectionTable>()..])
                .expect("get_entry_fa failed at parse section header!\n");
        let rva_start = section_header.virtual_address;
        let rva_end = section_header.virtual_address + section_header.virtual_size;
        if rva >= rva_start && rva <= rva_end {
            return rva - rva_start + section_header.pointer_to_raw_data;
        }
    }
    panic!("get_entry_fa failed!\n");
}

fn main() -> std::io::Result<()> {
    // Handle args
    let mut workspace = "".to_string();
    let mut binary_name = "".to_string();
    let mut target = "".to_string();
    let mut profile = "".to_string();
    let mut verbose = false;
    let mut strip_path = false;

    let mut cargo_home = "".to_string();
    let mut rustup_home = "".to_string();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("TD REPRODUCIBLE TOOL");
        ap.refer(&mut workspace).add_option(
            &["-w", "--workspace"],
            Store,
            "Where to find the target folder.",
        );
        ap.refer(&mut binary_name).add_option(
            &["-n", "--name"],
            Store,
            "Name for the compiled binary.",
        );
        ap.refer(&mut target)
            .add_option(&["-t", "--target"], Store, "The built target to find.");
        ap.refer(&mut profile).add_option(
            &["-p", "--profile"],
            Store,
            "The built profile to find.",
        );
        ap.refer(&mut cargo_home)
            .add_option(&["-c", "--cargo_home"], Store, "The cargo home.");
        ap.refer(&mut rustup_home)
            .add_option(&["-r", "--rustup_home"], Store, "The rustup home.");
        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue, "Verbose output.");
        ap.refer(&mut strip_path).add_option(
            &["-s", "--strip_path"],
            StoreTrue,
            "Strip rust file path.",
        );
        ap.parse_args_or_exit();
    }

    if target == "" {
        target = ".".to_string();
    } else if target == "x86_64-unknown-uefi" {
        if !binary_name.ends_with(".efi") {
            binary_name = binary_name + ".efi";
        }
    } else if target == "x86_64-unknown-none" {
        // Nothing to check
    }

    // Solve the path
    let binary_path: PathBuf = [
        if workspace == "" { "." } else { &workspace },
        "target",
        &target,
        if profile == "" { "release" } else { &profile },
        &binary_name,
    ]
    .iter()
    .collect();

    assert!(binary_path.exists());
    println!("INFO: Found the compiled file: {:?}", binary_path);

    // Load the binary
    let mut binary =
        File::open(binary_path.clone()).expect("Failed to open the compiled binary!\n");
    let mut buf = Vec::new();
    binary
        .read_to_end(&mut buf)
        .expect("Failed to read the compiled binary!\n");

    let mut pe_sig_off = 0;

    // Strip time data stamp in PE case
    if target == "x86_64-unknown-uefi"
        || binary_name.ends_with("exe")
        || binary_name.ends_with("efi")
    {
        pe_sig_off = u32::from_le_bytes(buf[PE_SIG_PTR_OFF..PE_SIG_PTR_OFF + 4].try_into().unwrap())
            as usize;
        let pe_sig = u32::from_le_bytes(buf[pe_sig_off..pe_sig_off + 4].try_into().unwrap());

        assert_eq!(
            pe_sig,
            u32::from_le_bytes([b'P', b'E', b'\0', b'\0']),
            "Found invalid PE signature!"
        );

        let time_stamp = u32::from_le_bytes(
            buf[pe_sig_off + TIMEDATASTAMP_OFF_TO_PE_SIG
                ..pe_sig_off + TIMEDATASTAMP_OFF_TO_PE_SIG + 4]
                .try_into()
                .unwrap(),
        );

        println!("INFO: Detected TimeDateStamp: {:?}", time_stamp);

        buf[pe_sig_off + TIMEDATASTAMP_OFF_TO_PE_SIG..pe_sig_off + TIMEDATASTAMP_OFF_TO_PE_SIG + 4]
            .zeroize();

        let time_stamp = u32::from_le_bytes(
            buf[pe_sig_off + TIMEDATASTAMP_OFF_TO_PE_SIG
                ..pe_sig_off + TIMEDATASTAMP_OFF_TO_PE_SIG + 4]
                .try_into()
                .unwrap(),
        );
        println!("INFO: After removing TimeDateStamp: {:?}", time_stamp);
    }

    // Strip timedatestamp and pdb guid(if any) in debug directory entry in PE case
    if target == "x86_64-unknown-uefi"
        || binary_name.ends_with("exe")
        || binary_name.ends_with("efi")
    {
        let size_of_optional_header = u16::from_le_bytes(
            buf[pe_sig_off + SIZE_OF_OPTIONAL_HEADER_OFF_TO_PE_SIG
                ..pe_sig_off + SIZE_OF_OPTIONAL_HEADER_OFF_TO_PE_SIG + 2]
                .try_into()
                .unwrap(),
        );
        assert_ne!(size_of_optional_header, 0);

        let file_type_magic = u16::from_le_bytes(
            buf[pe_sig_off + FILE_TYPE_MAGIC_OFF_TO_PE_SIG
                ..pe_sig_off + FILE_TYPE_MAGIC_OFF_TO_PE_SIG + 2]
                .try_into()
                .unwrap(),
        );
        assert_ne!(size_of_optional_header, 0);

        assert!(file_type_magic == PE32_MAGIC || file_type_magic == PE32_PLUS_MAGIC);

        let is_pe32_plus: bool = if file_type_magic == PE32_PLUS_MAGIC {
            true
        } else {
            false
        };

        let image_base: u64 = if is_pe32_plus {
            u64::from_le_bytes(
                buf[pe_sig_off + IMAGEBASE_OFF_TO_PE_SIG_PE32_PLUS
                    ..pe_sig_off + IMAGEBASE_OFF_TO_PE_SIG_PE32_PLUS + 8]
                    .try_into()
                    .unwrap(),
            )
        } else {
            u32::from_le_bytes(
                buf[pe_sig_off + IMAGEBASE_OFF_TO_PE_SIG_PE32
                    ..pe_sig_off + IMAGEBASE_OFF_TO_PE_SIG_PE32 + 4]
                    .try_into()
                    .unwrap(),
            ) as u64
        };

        assert_eq!(image_base % 0x10_000, 0);

        let section_alignment = u32::from_le_bytes(
            buf[pe_sig_off + SECTION_ALIGNMENT_OFF_TO_PE_SIG
                ..pe_sig_off + SECTION_ALIGNMENT_OFF_TO_PE_SIG + 4]
                .try_into()
                .unwrap(),
        );

        let file_alignment = u32::from_le_bytes(
            buf[pe_sig_off + FILE_ALIGNMENT_OFF_TO_PE_SIG
                ..pe_sig_off + FILE_ALIGNMENT_OFF_TO_PE_SIG + 4]
                .try_into()
                .unwrap(),
        );

        assert!(section_alignment >= file_alignment);
        assert_eq!(file_alignment % 2, 0);
        assert!(file_alignment >= 512 && file_alignment <= 0x10_000);

        let number_of_rva_and_sizes: u32 = if is_pe32_plus {
            u32::from_le_bytes(
                buf[pe_sig_off + NUMBER_OF_RVA_AND_SIZES_OFF_TO_PE_SIG_PE32_PLUS
                    ..pe_sig_off + NUMBER_OF_RVA_AND_SIZES_OFF_TO_PE_SIG_PE32_PLUS + 4]
                    .try_into()
                    .unwrap(),
            )
        } else {
            u32::from_le_bytes(
                buf[pe_sig_off + NUMBER_OF_RVA_AND_SIZES_OFF_TO_PE_SIG_PE32
                    ..pe_sig_off + NUMBER_OF_RVA_AND_SIZES_OFF_TO_PE_SIG_PE32 + 4]
                    .try_into()
                    .unwrap(),
            )
        };

        assert!(number_of_rva_and_sizes > DEBUG_TABLE_INDEX as u32);

        let debug_entry_rva: u32 = if is_pe32_plus {
            u32::from_le_bytes(
                buf[pe_sig_off + DEBUG_TABLE_OFF_TO_PE_SIG_PE32_PLUS
                    ..pe_sig_off + DEBUG_TABLE_OFF_TO_PE_SIG_PE32_PLUS + 4]
                    .try_into()
                    .unwrap(),
            )
        } else {
            u32::from_le_bytes(
                buf[pe_sig_off + DEBUG_TABLE_OFF_TO_PE_SIG_PE32
                    ..pe_sig_off + DEBUG_TABLE_OFF_TO_PE_SIG_PE32 + 4]
                    .try_into()
                    .unwrap(),
            )
        };

        let debug_entry_size: u32 = if is_pe32_plus {
            u32::from_le_bytes(
                buf[pe_sig_off + DEBUG_TABLE_OFF_TO_PE_SIG_PE32_PLUS + 4
                    ..pe_sig_off + DEBUG_TABLE_OFF_TO_PE_SIG_PE32_PLUS + 8]
                    .try_into()
                    .unwrap(),
            )
        } else {
            u32::from_le_bytes(
                buf[pe_sig_off + DEBUG_TABLE_OFF_TO_PE_SIG_PE32 + 4
                    ..pe_sig_off + DEBUG_TABLE_OFF_TO_PE_SIG_PE32 + 8]
                    .try_into()
                    .unwrap(),
            )
        };

        if verbose {
            println!(
                "INFO: Got debug directory entry rva: {:?}, size: {:?}\n",
                debug_entry_rva, debug_entry_size
            );
        }

        if debug_entry_rva != 0 && debug_entry_size != 0 {
            let number_of_sections = u16::from_le_bytes(
                buf[pe_sig_off + NUMBER_OF_SECTIONS_OFF_TO_PE_SIG
                    ..pe_sig_off + NUMBER_OF_SECTIONS_OFF_TO_PE_SIG + 2]
                    .try_into()
                    .unwrap(),
            );
            assert_ne!(number_of_sections, 0);

            let section_table_off: usize = if is_pe32_plus {
                DIRECTORY_ENTRY_START_OFF_TO_PE_SIG_PE32_PLUS + number_of_rva_and_sizes as usize * 8
            } else {
                DIRECTORY_ENTRY_START_OFF_TO_PE_SIG_PE32 + number_of_rva_and_sizes as usize * 8
            };
            let debug_entry_fa = get_entry_fa(
                section_table_off + pe_sig_off as usize,
                number_of_sections as usize,
                debug_entry_rva,
                &buf[..],
            );
            println!(
                "INFO: Found Debug direcotry entry with file address: {:02X?}, size: {:?}",
                debug_entry_fa, debug_entry_size
            );

            let debug_timedatastamp = u32::from_le_bytes(
                buf[debug_entry_fa as usize + DEBUG_TIMEDATESTAMP_OFF_TO_DEBUG_RVA
                    ..debug_entry_fa as usize + DEBUG_TIMEDATESTAMP_OFF_TO_DEBUG_RVA + 4]
                    .try_into()
                    .unwrap(),
            );

            println!(
                "INFO: Detected TimeDateStamp in debug directory: {:?}",
                debug_timedatastamp
            );

            buf[debug_entry_fa as usize + DEBUG_TIMEDATESTAMP_OFF_TO_DEBUG_RVA
                ..debug_entry_fa as usize + DEBUG_TIMEDATESTAMP_OFF_TO_DEBUG_RVA + 4]
                .copy_from_slice(&0u32.to_le_bytes());

            let debug_timedatastamp = u32::from_le_bytes(
                buf[debug_entry_fa as usize + DEBUG_TIMEDATESTAMP_OFF_TO_DEBUG_RVA
                    ..debug_entry_fa as usize + DEBUG_TIMEDATESTAMP_OFF_TO_DEBUG_RVA + 4]
                    .try_into()
                    .unwrap(),
            );
            println!(
                "INFO: After removing TimeDateStamp: {:?}",
                debug_timedatastamp
            );

            let debug_type = u32::from_le_bytes(
                buf[debug_entry_fa as usize + DEBUG_TYPE_OFF_TO_DEBUG_RVA
                    ..debug_entry_fa as usize + DEBUG_TYPE_OFF_TO_DEBUG_RVA + 4]
                    .try_into()
                    .unwrap(),
            );

            match debug_type {
                IMAGE_DEBUG_TYPE_CODEVIEW => {
                    // Strip the GUID of PDB, more info please check
                    // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
                    let pointer_to_raw_data = u32::from_le_bytes(
                        buf[debug_entry_fa as usize + POINTER_TO_RAW_DATA_OFF_TO_DEBUG_RVA
                            ..debug_entry_fa as usize + POINTER_TO_RAW_DATA_OFF_TO_DEBUG_RVA + 4]
                            .try_into()
                            .unwrap(),
                    );
                    assert!((pointer_to_raw_data as usize) < buf.len());
                    println!(
                        "INFO: Found the PDB GUID:{:02X?}",
                        buf[pointer_to_raw_data as usize + GUID_OFF_TO_DEBUG_DATA
                            ..pointer_to_raw_data as usize + GUID_OFF_TO_DEBUG_DATA + 16]
                            .into_iter()
                    );
                    buf[pointer_to_raw_data as usize + GUID_OFF_TO_DEBUG_DATA
                        ..pointer_to_raw_data as usize + GUID_OFF_TO_DEBUG_DATA + 16]
                        .copy_from_slice(&0u128.to_le_bytes());
                    println!(
                        "INFO: After removing, PDB GUID:{:02X?}",
                        buf[pointer_to_raw_data as usize + GUID_OFF_TO_DEBUG_DATA
                            ..pointer_to_raw_data as usize + GUID_OFF_TO_DEBUG_DATA + 16]
                            .into_iter()
                    );
                }
                _ => {
                    // Other type is of no interest to us now.
                }
            }
        } else {
            // Do nothing since the debug entry is invalid/absent
            if verbose {
                println!("INFO: Debug direcotry entry not found!");
            }
        }
    }

    // No more action is needed if strip_path is not specified.
    if !strip_path {
        println!(
            "INFO: -s or --strip_path is not specified, Skipping strip related rust file path."
        );
        fs::write(binary_path, buf).expect("Failed to open the compiled binary!\n");
        return Ok(());
    }

    // Check out CARGO_HOME and RUSTUP_HOME, proceed to strip rust file path.
    cargo_home = if cargo_home == "" {
        if env::var("CARGO_HOME").is_err() {
            panic!("Neither --cargo_home nor system environment for \"CARGO_HOME\" is found!\n")
        } else {
            env::var("CARGO_HOME").unwrap()
        }
    } else {
        cargo_home
    };

    rustup_home = if rustup_home == "" {
        if env::var("RUSTUP_HOME").is_err() {
            panic!("Neither --rustup_home nor system environment for \"RUSTUP_HOME\" is found!\n")
        } else {
            env::var("RUSTUP_HOME").unwrap()
        }
    } else {
        rustup_home
    };

    let mut cargo_like_path_to_strip_regex_pat_str = regex::escape(&cargo_home);
    cargo_like_path_to_strip_regex_pat_str.push_str(".*?\\.rs");
    let mut rustup_like_path_to_strip_regex_pat_str = regex::escape(&rustup_home);
    rustup_like_path_to_strip_regex_pat_str.push_str(".*?\\.rs");

    let cargo_like_path_to_strip_regex =
        Regex::new(&cargo_like_path_to_strip_regex_pat_str).unwrap();
    let rustup_like_path_to_strip_regex =
        Regex::new(&rustup_like_path_to_strip_regex_pat_str).unwrap();

    let mut stat = 0;
    let buf_read_only = buf.clone();
    for mat in cargo_like_path_to_strip_regex.find_iter(&buf_read_only) {
        stat += 1;
        if verbose {
            println!(
                "Found an item with start offset:{:?}, end offset:{:?}",
                mat.start(),
                mat.end()
            );
            println!("{:?}", std::str::from_utf8(mat.as_bytes()));
            println!("Now removing it!");
        }
        buf[mat.start()..mat.end()].zeroize();
    }

    for mat in rustup_like_path_to_strip_regex.find_iter(&buf_read_only) {
        stat += 1;
        if verbose {
            println!(
                "Found an item with start offset:{:?}, end offset:{:?}",
                mat.start(),
                mat.end()
            );
            println!("{:?}", std::str::from_utf8(mat.as_bytes()));
            println!("Now removing it!");
        }
        buf[mat.start()..mat.end()].zeroize();
    }

    println!("INFO: Removed {:?} items!", stat);

    fs::write(binary_path, buf).expect("Failed to open the compiled binary!\n");

    println!("INFO: Successful patched the compiled binary!");

    Ok(())
}

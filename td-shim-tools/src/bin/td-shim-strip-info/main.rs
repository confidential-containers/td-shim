// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use argparse::{ArgumentParser, Store, StoreTrue};
use regex::bytes::Regex;
use std::convert::TryInto;
use std::fs;
use std::io::Read;
use std::{env, fs::File, path::PathBuf};
use zeroize::Zeroize;

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
const PE_SIG_PTR_OFF: usize = 0x3C;
const TIMEDATASTAMP_OFF_TO_PE_SIG: usize = 0x8;

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

    // Strip time data stamp in PE case
    if target == "x86_64-unknown-uefi"
        || binary_name.ends_with("exe")
        || binary_name.ends_with("efi")
    {
        let pe_sig_off =
            u32::from_le_bytes(buf[PE_SIG_PTR_OFF..PE_SIG_PTR_OFF + 4].try_into().unwrap());
        let pe_sig = u32::from_le_bytes(
            buf[pe_sig_off as usize..pe_sig_off as usize + 4]
                .try_into()
                .unwrap(),
        );

        assert_eq!(
            pe_sig,
            u32::from_le_bytes([b'P', b'E', b'\0', b'\0']),
            "Found invalid PE signature!"
        );

        let time_stamp = u32::from_le_bytes(
            buf[pe_sig_off as usize + TIMEDATASTAMP_OFF_TO_PE_SIG
                ..pe_sig_off as usize + TIMEDATASTAMP_OFF_TO_PE_SIG + 4]
                .try_into()
                .unwrap(),
        );

        println!("INFO: Detected TimeDateStamp: {:?}", time_stamp);

        buf[pe_sig_off as usize + TIMEDATASTAMP_OFF_TO_PE_SIG
            ..pe_sig_off as usize + TIMEDATASTAMP_OFF_TO_PE_SIG + 4]
            .zeroize();

        let time_stamp = u32::from_le_bytes(
            buf[pe_sig_off as usize + TIMEDATASTAMP_OFF_TO_PE_SIG
                ..pe_sig_off as usize + TIMEDATASTAMP_OFF_TO_PE_SIG + 4]
                .try_into()
                .unwrap(),
        );
        println!("INFO: After removing TimeDateStamp: {:?}", time_stamp);
    }

    // No more action is needed if strip_path is not specified.
    if !strip_path {
        println!(
            "INFO: -s or --strip_path is not specified, Skipping strip related rust file path."
        );
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

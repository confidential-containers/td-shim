// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! td-shim-patch
//!
//! Unified patching tool for td-shim firmware images.
//! Subcommands: tdx-metadata, td-params, td-info

mod metadata;
mod td_info;
mod td_params;

fn print_help() {
    println!("td-shim-patch {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage: td-shim-patch <subcommand> [options]");
    println!();
    println!("Subcommands:");
    println!("    tdx-metadata  Patch TDX metadata signature and zero section attributes.");
    println!("    td-params     Patch the TD_PARAMS section from a JSON file.");
    println!("    td-info       Patch the TD_INFO section with a header + payload blob.");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_help();
        std::process::exit(1);
    }

    let subcommand = &args[1];
    // Pass remaining args (skip binary name and subcommand)
    let sub_args: Vec<String> = args[2..].to_vec();

    let result = match subcommand.as_str() {
        "tdx-metadata" => metadata::run(sub_args),
        "td-params" => td_params::run(sub_args),
        "td-info" => td_info::run(sub_args),
        "--help" | "-h" => {
            print_help();
            std::process::exit(0);
        }
        other => {
            eprintln!("Unknown subcommand: {other}");
            eprintln!();
            print_help();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e:?}");
        std::process::exit(1);
    }
}

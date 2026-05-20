// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Patches the TDX metadata signature in a td-shim firmware image and zeros
//! all section attributes. This is used to re-sign images for alternative
//! metadata consumers (e.g., NRX).

use std::mem::size_of;
use std::path::PathBuf;

use anyhow::Result;
use scroll::Pwrite;
use td_shim_interface::metadata::{
    TdxMetadataSection, TDX_METADATA_DESCRIPTOR_LEN, TDX_METADATA_SECTION_LEN,
};
use td_shim_tools::image::{Image, ParsedMetadata};

#[derive(Debug)]
struct Args {
    input: PathBuf,
    output: PathBuf,
    signature: u32,
}

fn patch_metadata(args: &Args) -> Result<()> {
    let mut image = Image::open(&args.input)?;
    let metadata = ParsedMetadata::from_image(&image)?;

    println!(
        "TDX Metadata found at offset 0x{:x}",
        metadata.descriptor_offset
    );
    println!(
        "  Current signature: 0x{:08x}",
        metadata.descriptor.signature
    );
    println!("  Sections: {}", metadata.sections.len());

    // Patch signature in the descriptor
    let desc_off = metadata.descriptor_offset;
    image
        .binary
        .pwrite_with(args.signature, desc_off, scroll::LE)
        .map_err(|e| anyhow::anyhow!("failed to write signature: {e}"))?;

    println!("  New signature: 0x{:08x}", args.signature);

    // Zero all section attributes
    let sections_start = desc_off + TDX_METADATA_DESCRIPTOR_LEN as usize;
    for i in 0..metadata.sections.len() {
        let section_off = sections_start + i * TDX_METADATA_SECTION_LEN as usize;
        // attributes is the last u32 in TdxMetadataSection (offset 28 within the section)
        let attr_off = section_off + size_of::<TdxMetadataSection>() - size_of::<u32>();
        image
            .binary
            .pwrite_with(0u32, attr_off, scroll::LE)
            .map_err(|e| anyhow::anyhow!("failed to zero attributes for section {i}: {e}"))?;
    }

    println!(
        "  Zeroed attributes for all {} sections",
        metadata.sections.len()
    );

    image.write(&args.output)?;
    println!("Patched image written to: {}", args.output.display());

    Ok(())
}

fn show_help() {
    eprintln!("td-shim-patch tdx-metadata");
    eprintln!();
    eprintln!("Patches TDX metadata signature and zeros section attributes.");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("    --in <path>          Input firmware image (required).");
    eprintln!("    --out <path>         Output firmware image (required).");
    eprintln!(
        "    --signature <hex>    New metadata signature as hex (e.g., 0x58524e5f) (required)."
    );
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    if let Some(stripped) = s.strip_prefix("0x") {
        u32::from_str_radix(stripped, 16).ok()
    } else if let Some(stripped) = s.strip_prefix("0X") {
        u32::from_str_radix(stripped, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

fn prepare_args(args_list: Vec<String>) -> Option<Args> {
    use std::collections::VecDeque;
    let mut args_list: VecDeque<String> = args_list.into();

    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut signature: Option<u32> = None;

    while let Some(cur) = args_list.pop_front() {
        match cur.as_str() {
            "--in" => {
                if let Some(path) = args_list.pop_front() {
                    input = Some(PathBuf::from(path));
                } else {
                    eprintln!("Parameter to --in is missing!");
                    return None;
                }
            }
            "--out" => {
                if let Some(path) = args_list.pop_front() {
                    output = Some(PathBuf::from(path));
                } else {
                    eprintln!("Parameter to --out is missing!");
                    return None;
                }
            }
            "--signature" => {
                if let Some(sig_str) = args_list.pop_front() {
                    if let Some(sig) = parse_hex_u32(&sig_str) {
                        signature = Some(sig);
                    } else {
                        eprintln!("Failed to parse --signature value: {sig_str}");
                        return None;
                    }
                } else {
                    eprintln!("Parameter to --signature is missing!");
                    return None;
                }
            }
            _ => {
                eprintln!("Unknown argument: {cur}");
                return None;
            }
        }
    }

    if input.is_none() || output.is_none() || signature.is_none() {
        return None;
    }

    Some(Args {
        input: input.unwrap(),
        output: output.unwrap(),
        signature: signature.unwrap(),
    })
}

pub fn run(args: Vec<String>) -> Result<()> {
    if let Some(parsed) = prepare_args(args) {
        patch_metadata(&parsed)
    } else {
        show_help();
        std::process::exit(1);
    }
}

// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Patches the TD_INFO section of a td-shim firmware image with a generic
//! header (GUID, length, version, SVN) and an opaque payload-specific binary
//! blob. The blob format is defined by the caller (TD type specific).

use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use td_shim_interface::metadata::TDX_METADATA_SECTION_TYPE_TD_INFO;
use td_shim_tools::image::{Image, ParsedMetadata};

/// TD_INFO generic header: guid(16) + length(4) + version(4) + svn(4) = 28 bytes
const TD_INFO_HEADER_SIZE: usize = 28;

#[derive(Debug)]
struct Args {
    input: PathBuf,
    output: PathBuf,
    guid: [u8; 16],
    version: u32,
    svn: u32,
    payload_info: PathBuf,
}

fn patch_td_info(args: &Args) -> Result<()> {
    let mut image = Image::open(&args.input)?;
    let metadata = ParsedMetadata::from_image(&image)?;

    let section = metadata
        .find_section(TDX_METADATA_SECTION_TYPE_TD_INFO)
        .context("TD_INFO section not found in TDX metadata")?;

    let offset = section.data_offset as usize;
    let max_size = section.raw_data_size as usize;
    ensure!(
        offset + max_size <= image.binary.len(),
        "TD_INFO section extends beyond image bounds"
    );

    // Read the payload-info blob
    let payload_blob = std::fs::read(&args.payload_info)
        .with_context(|| format!("failed to read {}", args.payload_info.display()))?;

    let total_size = TD_INFO_HEADER_SIZE + payload_blob.len();
    ensure!(
        total_size <= max_size,
        "TD_INFO data ({total_size} bytes) exceeds section capacity ({max_size} bytes)",
    );

    // Zero the entire section first
    image.binary[offset..offset + max_size].fill(0);

    // Write generic header
    let mut pos = offset;

    // GUID (16 bytes)
    image.binary[pos..pos + 16].copy_from_slice(&args.guid);
    pos += 16;

    // Length (4 bytes, LE) — total size of TdInfo including header + payload
    let length = total_size as u32;
    image.binary[pos..pos + 4].copy_from_slice(&length.to_le_bytes());
    pos += 4;

    // Version (4 bytes, LE)
    image.binary[pos..pos + 4].copy_from_slice(&args.version.to_le_bytes());
    pos += 4;

    // SVN (4 bytes, LE)
    image.binary[pos..pos + 4].copy_from_slice(&args.svn.to_le_bytes());
    pos += 4;

    // Payload-specific blob
    image.binary[pos..pos + payload_blob.len()].copy_from_slice(&payload_blob);

    println!("TD_INFO patched at offset 0x{offset:x}");
    println!("  GUID: {:02x?}", args.guid);
    println!("  Length: {total_size} (0x{total_size:x})");
    println!("  Version: 0x{:08x}", args.version);
    println!("  SVN: {}", args.svn);
    println!(
        "  Payload info: {} bytes from {}",
        payload_blob.len(),
        args.payload_info.display()
    );

    image.write(&args.output)?;
    println!("Patched image written to: {}", args.output.display());

    Ok(())
}

/// Parse a GUID string in the form "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
/// into 16 bytes in mixed-endian format (matching UEFI PI GUID encoding).
fn parse_guid(s: &str) -> Option<[u8; 16]> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return None;
    }

    // Validate expected field lengths: 8-4-4-4-12
    if parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
    {
        return None;
    }

    let d1 = u32::from_str_radix(parts[0], 16).ok()?;
    let d2 = u16::from_str_radix(parts[1], 16).ok()?;
    let d3 = u16::from_str_radix(parts[2], 16).ok()?;
    let d4 = u16::from_str_radix(parts[3], 16).ok()?;
    let d5 = u64::from_str_radix(parts[4], 16).ok()?;

    let mut guid = [0u8; 16];
    // First three fields are little-endian (UEFI mixed-endian GUID)
    guid[0..4].copy_from_slice(&d1.to_le_bytes());
    guid[4..6].copy_from_slice(&d2.to_le_bytes());
    guid[6..8].copy_from_slice(&d3.to_le_bytes());
    // Last two fields are big-endian
    guid[8..10].copy_from_slice(&d4.to_be_bytes());
    guid[10..16].copy_from_slice(&d5.to_be_bytes()[2..8]);

    Some(guid)
}

/// Parse version string "major.minor.update" into packed u32:
/// (major << 24) | (minor << 16) | update
fn parse_version(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse::<u8>().ok()?;
    let minor = parts[1].parse::<u8>().ok()?;
    let update = parts[2].parse::<u16>().ok()?;
    Some(((major as u32) << 24) | ((minor as u32) << 16) | (update as u32))
}

fn show_help() {
    eprintln!("td-shim-patch td-info");
    eprintln!();
    eprintln!("Patches the TD_INFO section with a generic header + payload-specific blob.");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("    --in <path>              Input firmware image (required).");
    eprintln!("    --out <path>             Output firmware image (required).");
    eprintln!("    --guid <guid>            TD type GUID, e.g. 6d8415a6-5701-0247-a696-c0420ce3b4e9 (required).");
    eprintln!("    --version <a.b.c>        Release version as major.minor.update (required).");
    eprintln!("    --svn <n>                Security Version Number (required).");
    eprintln!("    --payload-info <path>    Binary blob with TD-type-specific info (required).");
}

fn prepare_args(args_list: Vec<String>) -> Option<Args> {
    use std::collections::VecDeque;
    let mut args_list: VecDeque<String> = args_list.into();

    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut guid: Option<[u8; 16]> = None;
    let mut version: Option<u32> = None;
    let mut svn: Option<u32> = None;
    let mut payload_info: Option<PathBuf> = None;

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
            "--guid" => {
                if let Some(guid_str) = args_list.pop_front() {
                    if let Some(g) = parse_guid(&guid_str) {
                        guid = Some(g);
                    } else {
                        eprintln!("Failed to parse GUID: {guid_str}");
                        return None;
                    }
                } else {
                    eprintln!("Parameter to --guid is missing!");
                    return None;
                }
            }
            "--version" => {
                if let Some(ver_str) = args_list.pop_front() {
                    if let Some(v) = parse_version(&ver_str) {
                        version = Some(v);
                    } else {
                        eprintln!(
                            "Failed to parse version: {ver_str} (expected major.minor.update)"
                        );
                        return None;
                    }
                } else {
                    eprintln!("Parameter to --version is missing!");
                    return None;
                }
            }
            "--svn" => {
                if let Some(svn_str) = args_list.pop_front() {
                    if let Ok(s) = svn_str.parse::<u32>() {
                        svn = Some(s);
                    } else {
                        eprintln!("Failed to parse SVN: {svn_str}");
                        return None;
                    }
                } else {
                    eprintln!("Parameter to --svn is missing!");
                    return None;
                }
            }
            "--payload-info" => {
                if let Some(path) = args_list.pop_front() {
                    payload_info = Some(PathBuf::from(path));
                } else {
                    eprintln!("Parameter to --payload-info is missing!");
                    return None;
                }
            }
            _ => {
                eprintln!("Unknown argument: {cur}");
                return None;
            }
        }
    }

    if input.is_none()
        || output.is_none()
        || guid.is_none()
        || version.is_none()
        || svn.is_none()
        || payload_info.is_none()
    {
        return None;
    }

    Some(Args {
        input: input.unwrap(),
        output: output.unwrap(),
        guid: guid.unwrap(),
        version: version.unwrap(),
        svn: svn.unwrap(),
        payload_info: payload_info.unwrap(),
    })
}

pub fn run(args: Vec<String>) -> Result<()> {
    if let Some(parsed) = prepare_args(args) {
        patch_td_info(&parsed)
    } else {
        show_help();
        std::process::exit(1);
    }
}

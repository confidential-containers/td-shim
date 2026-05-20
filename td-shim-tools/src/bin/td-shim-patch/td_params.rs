// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Patches the TD_PARAMS section of a td-shim firmware image from a JSON file.
//! The JSON file must contain the full 1024-byte TD_PARAMS structure serialized
//! as a flat JSON object with fields matching the TDX TD_PARAMS layout.

use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use td_shim_interface::metadata::TDX_METADATA_SECTION_TYPE_TD_PARAMS;
use td_shim_tools::image::{Image, ParsedMetadata};

/// TD_PARAMS is exactly 1024 bytes (as defined in TDX Module spec).
const TD_PARAMS_SIZE: usize = 1024;

#[derive(Debug)]
struct Args {
    input: PathBuf,
    output: PathBuf,
    tdparams_json: PathBuf,
}

fn patch_params(args: &Args) -> Result<()> {
    let mut image = Image::open(&args.input)?;
    let metadata = ParsedMetadata::from_image(&image)?;

    let section = metadata
        .find_section(TDX_METADATA_SECTION_TYPE_TD_PARAMS)
        .context("TD_PARAMS section not found in TDX metadata")?;

    let offset = section.data_offset as usize;
    let size = section.raw_data_size as usize;
    ensure!(
        size >= TD_PARAMS_SIZE,
        "TD_PARAMS section too small: {size} bytes, need {TD_PARAMS_SIZE}",
    );
    ensure!(
        offset + size <= image.binary.len(),
        "TD_PARAMS section extends beyond image bounds"
    );

    // Read the JSON file as raw bytes and deserialize into the TD_PARAMS region.
    // The JSON structure should produce exactly TD_PARAMS_SIZE bytes when serialized.
    let json_content = std::fs::read_to_string(&args.tdparams_json)
        .with_context(|| format!("failed to read {}", args.tdparams_json.display()))?;

    let td_params: serde_json::Value = serde_json::from_str(&json_content)
        .with_context(|| format!("failed to parse {}", args.tdparams_json.display()))?;

    // Serialize the TD_PARAMS fields into the binary region.
    // We expect the JSON to contain hex-string fields that map to the TD_PARAMS structure.
    let params_bytes = serialize_td_params(&td_params)?;
    ensure!(
        params_bytes.len() == TD_PARAMS_SIZE,
        "serialized TD_PARAMS is {} bytes, expected {TD_PARAMS_SIZE}",
        params_bytes.len(),
    );

    image.binary[offset..offset + TD_PARAMS_SIZE].copy_from_slice(&params_bytes);

    println!("TD_PARAMS patched at offset 0x{offset:x} ({TD_PARAMS_SIZE} bytes)");

    image.write(&args.output)?;
    println!("Patched image written to: {}", args.output.display());

    Ok(())
}

/// Serialize TD_PARAMS JSON into the 1024-byte binary layout.
///
/// Expected JSON fields (all values as hex strings or integers):
/// - attributes (u64), xfam (u64), maxvcpus (u16), numl2vms (u8),
///   msrconfigctls (u8), reserved (u32), eptpcontrols (u64), configflags (u64),
///   tscfrequency (u16), reserved2 ([u8;38]), mrconfigid ([u8;48]),
///   mrowner ([u8;48]), mrownerconfig ([u8;48]), ia32archcapabilitiesconfig (u64),
///   mrconfigsvn (u16), mrownerconfigsvn (u16), reserved3 ([u8;20]),
///   cpuid_config ([u8;768])
fn serialize_td_params(value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; TD_PARAMS_SIZE];
    let mut offset = 0usize;

    let write_u64 =
        |buf: &mut Vec<u8>, off: &mut usize, v: &serde_json::Value, name: &str| -> Result<()> {
            let val = parse_json_u64(v, name)?;
            buf[*off..*off + 8].copy_from_slice(&val.to_le_bytes());
            *off += 8;
            Ok(())
        };
    let write_u32 =
        |buf: &mut Vec<u8>, off: &mut usize, v: &serde_json::Value, name: &str| -> Result<()> {
            let val = parse_json_u32(v, name)?;
            buf[*off..*off + 4].copy_from_slice(&val.to_le_bytes());
            *off += 4;
            Ok(())
        };
    let write_u16 =
        |buf: &mut Vec<u8>, off: &mut usize, v: &serde_json::Value, name: &str| -> Result<()> {
            let val = parse_json_u16(v, name)?;
            buf[*off..*off + 2].copy_from_slice(&val.to_le_bytes());
            *off += 2;
            Ok(())
        };
    let write_u8 =
        |buf: &mut Vec<u8>, off: &mut usize, v: &serde_json::Value, name: &str| -> Result<()> {
            let val = parse_json_u8(v, name)?;
            buf[*off] = val;
            *off += 1;
            Ok(())
        };
    let write_bytes = |buf: &mut Vec<u8>,
                       off: &mut usize,
                       v: &serde_json::Value,
                       name: &str,
                       len: usize|
     -> Result<()> {
        let bytes = parse_json_bytes(v, name, len)?;
        buf[*off..*off + len].copy_from_slice(&bytes);
        *off += len;
        Ok(())
    };

    write_u64(&mut buf, &mut offset, value, "attributes")?;
    write_u64(&mut buf, &mut offset, value, "xfam")?;
    write_u16(&mut buf, &mut offset, value, "maxvcpus")?;
    write_u8(&mut buf, &mut offset, value, "numl2vms")?;
    write_u8(&mut buf, &mut offset, value, "msrconfigctls")?;
    write_u32(&mut buf, &mut offset, value, "reserved")?;
    write_u64(&mut buf, &mut offset, value, "eptpcontrols")?;
    write_u64(&mut buf, &mut offset, value, "configflags")?;
    write_u16(&mut buf, &mut offset, value, "tscfrequency")?;
    write_bytes(&mut buf, &mut offset, value, "reserved2", 38)?;
    write_bytes(&mut buf, &mut offset, value, "mrconfigid", 48)?;
    write_bytes(&mut buf, &mut offset, value, "mrowner", 48)?;
    write_bytes(&mut buf, &mut offset, value, "mrownerconfig", 48)?;
    write_u64(&mut buf, &mut offset, value, "ia32archcapabilitiesconfig")?;
    write_u16(&mut buf, &mut offset, value, "mrconfigsvn")?;
    write_u16(&mut buf, &mut offset, value, "mrownerconfigsvn")?;
    write_bytes(&mut buf, &mut offset, value, "reserved3", 20)?;
    write_bytes(&mut buf, &mut offset, value, "cpuid_config", 768)?;

    ensure!(
        offset == TD_PARAMS_SIZE,
        "TD_PARAMS serialization offset mismatch: got {offset}, expected {TD_PARAMS_SIZE}"
    );
    Ok(buf)
}

fn parse_json_u64(obj: &serde_json::Value, field: &str) -> Result<u64> {
    match obj.get(field) {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .context(format!("field '{field}' is not a valid u64")),
        Some(serde_json::Value::String(s)) => {
            parse_hex_u64(s).with_context(|| format!("field '{field}' has invalid hex value '{s}'"))
        }
        Some(_) => anyhow::bail!("field '{field}' has unexpected type"),
        None => Ok(0),
    }
}

fn parse_json_u32(obj: &serde_json::Value, field: &str) -> Result<u32> {
    match obj.get(field) {
        Some(serde_json::Value::Number(n)) => {
            let v = n
                .as_u64()
                .context(format!("field '{field}' is not a valid u32"))?;
            ensure!(
                v <= u32::MAX as u64,
                "field '{field}' value {v} overflows u32"
            );
            Ok(v as u32)
        }
        Some(serde_json::Value::String(s)) => {
            parse_hex_u32(s).with_context(|| format!("field '{field}' has invalid hex value '{s}'"))
        }
        Some(_) => anyhow::bail!("field '{field}' has unexpected type"),
        None => Ok(0),
    }
}

fn parse_json_u16(obj: &serde_json::Value, field: &str) -> Result<u16> {
    match obj.get(field) {
        Some(serde_json::Value::Number(n)) => {
            let v = n
                .as_u64()
                .context(format!("field '{field}' is not a valid u16"))?;
            ensure!(
                v <= u16::MAX as u64,
                "field '{field}' value {v} overflows u16"
            );
            Ok(v as u16)
        }
        Some(serde_json::Value::String(s)) => {
            parse_hex_u16(s).with_context(|| format!("field '{field}' has invalid hex value '{s}'"))
        }
        Some(_) => anyhow::bail!("field '{field}' has unexpected type"),
        None => Ok(0),
    }
}

fn parse_json_u8(obj: &serde_json::Value, field: &str) -> Result<u8> {
    match obj.get(field) {
        Some(serde_json::Value::Number(n)) => {
            let v = n
                .as_u64()
                .context(format!("field '{field}' is not a valid u8"))?;
            ensure!(
                v <= u8::MAX as u64,
                "field '{field}' value {v} overflows u8"
            );
            Ok(v as u8)
        }
        Some(serde_json::Value::String(s)) => {
            parse_hex_u8(s).with_context(|| format!("field '{field}' has invalid hex value '{s}'"))
        }
        Some(_) => anyhow::bail!("field '{field}' has unexpected type"),
        None => Ok(0),
    }
}

fn parse_json_bytes(obj: &serde_json::Value, field: &str, expected_len: usize) -> Result<Vec<u8>> {
    match obj.get(field) {
        Some(serde_json::Value::String(s)) => {
            let bytes = hex::decode(s.trim_start_matches("0x").trim_start_matches("0X"))
                .with_context(|| format!("field '{field}' has invalid hex bytes"))?;
            ensure!(
                bytes.len() == expected_len,
                "field '{field}': expected {expected_len} bytes, got {}",
                bytes.len()
            );
            Ok(bytes)
        }
        Some(serde_json::Value::Array(arr)) => {
            let mut bytes = Vec::with_capacity(expected_len);
            for (i, v) in arr.iter().enumerate() {
                let val = v
                    .as_u64()
                    .with_context(|| format!("field '{field}' element {i} is not a number"))?;
                ensure!(
                    val <= u8::MAX as u64,
                    "field '{field}' element {i} value {val} overflows u8"
                );
                bytes.push(val as u8);
            }
            ensure!(
                bytes.len() == expected_len,
                "field '{field}': expected {expected_len} bytes, got {}",
                bytes.len()
            );
            Ok(bytes)
        }
        Some(_) => anyhow::bail!("field '{field}' has unexpected type"),
        None => Ok(vec![0u8; expected_len]),
    }
}

fn parse_hex_u64(s: &str) -> Result<u64> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).with_context(|| format!("invalid hex u64: {s}"))
}

fn parse_hex_u32(s: &str) -> Result<u32> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).with_context(|| format!("invalid hex u32: {s}"))
}

fn parse_hex_u16(s: &str) -> Result<u16> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(s, 16).with_context(|| format!("invalid hex u16: {s}"))
}

fn parse_hex_u8(s: &str) -> Result<u8> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u8::from_str_radix(s, 16).with_context(|| format!("invalid hex u8: {s}"))
}

fn show_help() {
    eprintln!("td-shim-patch td-params");
    eprintln!();
    eprintln!("Patches the TD_PARAMS section of a td-shim firmware image from JSON.");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("    --in <path>          Input firmware image (required).");
    eprintln!("    --out <path>         Output firmware image (required).");
    eprintln!("    --tdparams <path>    TD_PARAMS JSON file (required).");
}

fn prepare_args(args_list: Vec<String>) -> Option<Args> {
    use std::collections::VecDeque;
    let mut args_list: VecDeque<String> = args_list.into();

    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut tdparams_json: Option<PathBuf> = None;

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
            "--tdparams" => {
                if let Some(path) = args_list.pop_front() {
                    tdparams_json = Some(PathBuf::from(path));
                } else {
                    eprintln!("Parameter to --tdparams is missing!");
                    return None;
                }
            }
            _ => {
                eprintln!("Unknown argument: {cur}");
                return None;
            }
        }
    }

    if input.is_none() || output.is_none() || tdparams_json.is_none() {
        return None;
    }

    Some(Args {
        input: input.unwrap(),
        output: output.unwrap(),
        tdparams_json: tdparams_json.unwrap(),
    })
}

pub fn run(args: Vec<String>) -> Result<()> {
    if let Some(parsed) = prepare_args(args) {
        patch_params(&parsed)
    } else {
        show_help();
        std::process::exit(1);
    }
}

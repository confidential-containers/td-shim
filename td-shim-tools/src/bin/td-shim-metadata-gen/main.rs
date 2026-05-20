// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TDX Metadata JSON Generator
//!
//! Generates a TDX metadata JSON file consumable by `td-shim-ld --metadata`.
//! Reads an image layout JSON (as produced by td-shim-image-layout-gen) and
//! computes metadata section offsets from the section order. TdParams and TdInfo
//! sections are included only if present in the layout with non-zero size.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// CLI argument names
const LAYOUT: &str = "--layout";
const MEMORY_LAYOUT: &str = "--memory-layout";
const OUTPUT: &str = "--out";

/// A single metadata section in the output.
#[derive(Clone, Debug, Serialize)]
struct SectionConfig {
    #[serde(rename = "Type")]
    r#type: String,
    #[serde(rename = "Attributes")]
    attributes: String,
    #[serde(rename = "DataOffset")]
    data_offset: String,
    #[serde(rename = "RawDataSize")]
    raw_data_size: String,
    #[serde(rename = "MemoryAddress")]
    memory_address: String,
    #[serde(rename = "MemoryDataSize")]
    memory_data_size: String,
}

/// Output format matching what `td-shim-ld --metadata` expects.
#[derive(Clone, Debug, Serialize)]
struct MetadataOutput {
    #[serde(rename = "Sections")]
    sections: Vec<SectionConfig>,
}

fn show_help() {
    println!("td-shim-metadata-gen {VERSION}");
    println!();
    println!("Generates TDX metadata JSON for td-shim-ld from an image layout.");
    println!();
    println!("Usage:");
    println!("    td-shim-metadata-gen {LAYOUT} <path> {OUTPUT} <path> [{MEMORY_LAYOUT} <path>]");
    println!();
    println!("Arguments:");
    println!("    {LAYOUT} <path>           Image layout JSON (from td-shim-image-layout-gen).");
    println!("    {OUTPUT} <path>           Output metadata JSON file path.");
    println!("    {MEMORY_LAYOUT} <path>    Memory layout JSON with PermMem regions (optional).");
    println!();
    println!("The tool reads the image layout JSON, computes section offsets, and emits");
    println!("metadata for BFV, TempMem, Payload, and optionally TdParams/TdInfo.");
    println!("When --memory-layout is provided, PermMem sections are included.");
}

/// Parse a hex string like "0x20000" into u32.
fn parse_hex(s: &str) -> Result<u32> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).with_context(|| format!("failed to parse hex value: {s}"))
}

/// Parse a hex string into u64.
fn parse_hex_u64(s: &str) -> Result<u64> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).with_context(|| format!("failed to parse hex value: {s}"))
}

/// A memory region parsed from the memory layout file.
struct MemoryRegion {
    address: u64,
    size: u64,
}

/// Parsed memory layout with PermMem and additional TempMem regions.
struct MemoryLayoutConfig {
    perm_mem: Vec<MemoryRegion>,
    temp_mem: Vec<MemoryRegion>,
}

/// Parse the memory layout JSON file.
fn parse_memory_layout(path: &PathBuf) -> Result<MemoryLayoutConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let parse_regions = |key: &str| -> Result<Vec<MemoryRegion>> {
        match json.get(key).and_then(|v| v.as_array()) {
            Some(arr) => {
                let mut regions = Vec::new();
                for entry in arr {
                    let addr_str = entry["address"]
                        .as_str()
                        .with_context(|| format!("{key} entry missing 'address'"))?;
                    let size_str = entry["size"]
                        .as_str()
                        .with_context(|| format!("{key} entry missing 'size'"))?;
                    regions.push(MemoryRegion {
                        address: parse_hex_u64(addr_str)?,
                        size: parse_hex_u64(size_str)?,
                    });
                }
                Ok(regions)
            }
            None => Ok(Vec::new()),
        }
    };

    Ok(MemoryLayoutConfig {
        perm_mem: parse_regions("PermMem")?,
        temp_mem: parse_regions("TempMem")?,
    })
}

fn generate_from_layout(
    layout_path: &PathBuf,
    memory_layout: &MemoryLayoutConfig,
    output: &PathBuf,
) -> Result<()> {
    let content = std::fs::read_to_string(layout_path)
        .with_context(|| format!("failed to read {}", layout_path.display()))?;

    let layout: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", layout_path.display()))?;

    let obj = layout
        .as_object()
        .context("layout JSON must be an object")?;

    let image_size = obj
        .get("ImageSize")
        .and_then(|v| v.as_str())
        .context("ImageSize not found in layout")?;
    let image_size = parse_hex(image_size)?;
    let firmware_base = 0x1_0000_0000u64.wrapping_sub(image_size as u64) as u32;

    // Section order (NRX): TempStack, TempHeap, Payload, TdInfo, TdParams, Metadata, Ipl, ResetVector
    let section_order = [
        "TempStack",
        "TempHeap",
        "Payload",
        "TdInfo",
        "TdParams",
        "Metadata",
        "Ipl",
        "ResetVector",
    ];

    // Compute cumulative offsets
    let mut offset = 0u32;
    let mut section_offsets: Vec<(&str, u32, u32)> = Vec::new(); // (name, offset, size)
    for name in &section_order {
        if let Some(val) = obj.get(*name).and_then(|v| v.as_str()) {
            let size = parse_hex(val)?;
            section_offsets.push((name, offset, size));
            offset += size;
        }
    }

    // Find specific sections
    let find = |name: &str| -> Option<(u32, u32)> {
        section_offsets
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, off, sz)| (*off, *sz))
    };

    let mut sections = Vec::new();

    // TdParams (optional)
    if let Some((td_params_off, td_params_sz)) = find("TdParams") {
        if td_params_sz > 0 {
            sections.push(SectionConfig {
                r#type: "TdParams".to_string(),
                attributes: "0x0".to_string(),
                data_offset: format!("0x{:X}", td_params_off),
                raw_data_size: format!("0x{:X}", td_params_sz),
                memory_address: "0x0".to_string(),
                memory_data_size: "0x0".to_string(),
            });
        }
    }

    // BFV: starts at the earliest of TdInfo/TdParams (both must be within BFV)
    // and extends to end of image.
    let bfv_start = find("TdInfo")
        .filter(|(_, sz)| *sz > 0)
        .map(|(off, _)| off)
        .into_iter()
        .chain(
            find("TdParams")
                .filter(|(_, sz)| *sz > 0)
                .map(|(off, _)| off)
                .into_iter(),
        )
        .chain(find("Metadata").map(|(off, _)| off).into_iter())
        .chain(find("Ipl").map(|(off, _)| off).into_iter())
        .min()
        .unwrap_or(0);
    let bfv_size = image_size - bfv_start;
    let bfv_base = firmware_base.wrapping_add(bfv_start);

    sections.push(SectionConfig {
        r#type: "BFV".to_string(),
        attributes: "0x1".to_string(),
        data_offset: format!("0x{:X}", bfv_start),
        raw_data_size: format!("0x{:X}", bfv_size),
        memory_address: format!("0x{:X}", bfv_base),
        memory_data_size: format!("0x{:X}", bfv_size),
    });

    // TempMem: combine TempStack + TempHeap from image layout
    let temp_stack = find("TempStack");
    let temp_heap = find("TempHeap");
    if let Some((stack_off, stack_sz)) = temp_stack {
        let heap_sz = temp_heap.map(|(_, sz)| sz).unwrap_or(0);
        let total = stack_sz + heap_sz;
        let base = firmware_base.wrapping_add(stack_off);
        sections.push(SectionConfig {
            r#type: "TempMem".to_string(),
            attributes: "0x0".to_string(),
            data_offset: "0x0".to_string(),
            raw_data_size: "0x0".to_string(),
            memory_address: format!("0x{:X}", base),
            memory_data_size: format!("0x{:X}", total),
        });
    }

    // Additional TempMem regions from memory layout
    for region in &memory_layout.temp_mem {
        if region.size > 0 {
            sections.push(SectionConfig {
                r#type: "TempMem".to_string(),
                attributes: "0x0".to_string(),
                data_offset: "0x0".to_string(),
                raw_data_size: "0x0".to_string(),
                memory_address: format!("0x{:X}", region.address),
                memory_data_size: format!("0x{:X}", region.size),
            });
        }
    }

    // Payload
    if let Some((payload_off, payload_sz)) = find("Payload") {
        if payload_sz > 0 {
            let base = firmware_base.wrapping_add(payload_off);
            sections.push(SectionConfig {
                r#type: "Payload".to_string(),
                attributes: "0x1".to_string(),
                data_offset: format!("0x{:X}", payload_off),
                raw_data_size: format!("0x{:X}", payload_sz),
                memory_address: format!("0x{:X}", base),
                memory_data_size: format!("0x{:X}", payload_sz),
            });
        }
    }

    // TdInfo (optional)
    if let Some((td_info_off, td_info_sz)) = find("TdInfo") {
        if td_info_sz > 0 {
            sections.push(SectionConfig {
                r#type: "TdInfo".to_string(),
                attributes: "0x0".to_string(),
                data_offset: format!("0x{:X}", td_info_off),
                raw_data_size: format!("0x{:X}", td_info_sz),
                memory_address: "0x0".to_string(),
                memory_data_size: "0x0".to_string(),
            });
        }
    }

    // PermMem (VMM-allocated permanent memory via PAGE_AUG)
    for region in &memory_layout.perm_mem {
        if region.size > 0 {
            sections.push(SectionConfig {
                r#type: "PermMem".to_string(),
                attributes: "0x2".to_string(),
                data_offset: "0x0".to_string(),
                raw_data_size: "0x0".to_string(),
                memory_address: format!("0x{:X}", region.address),
                memory_data_size: format!("0x{:X}", region.size),
            });
        }
    }

    // Validate no memory region overlaps
    check_memory_overlaps(&sections)?;

    let output_data = MetadataOutput { sections };
    let json = serde_json::to_string_pretty(&output_data)?;
    std::fs::write(output, &json)
        .with_context(|| format!("failed to write output to {}", output.display()))?;

    println!("TDX metadata JSON written to: {}", output.display());
    Ok(())
}

/// Check that no two sections with non-zero memory ranges overlap.
fn check_memory_overlaps(sections: &[SectionConfig]) -> Result<()> {
    let ranges: Vec<(&str, u64, u64)> = sections
        .iter()
        .filter_map(|s| {
            let addr = parse_hex_u64(&s.memory_address).ok()?;
            let size = parse_hex_u64(&s.memory_data_size).ok()?;
            if size == 0 {
                return None;
            }
            Some((s.r#type.as_str(), addr, size))
        })
        .collect();

    for i in 0..ranges.len() {
        for j in (i + 1)..ranges.len() {
            let (name_a, start_a, size_a) = ranges[i];
            let (name_b, start_b, size_b) = ranges[j];
            let end_a = start_a + size_a;
            let end_b = start_b + size_b;
            if start_a < end_b && start_b < end_a {
                anyhow::bail!(
                    "memory overlap: {name_a} [0x{start_a:X}..0x{end_a:X}) overlaps \
                     {name_b} [0x{start_b:X}..0x{end_b:X})"
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Args {
    layout: PathBuf,
    memory_layout: Option<PathBuf>,
    output: PathBuf,
}

fn prepare_args() -> Option<Args> {
    use std::collections::VecDeque;
    use std::env;
    let mut args_list: VecDeque<String> = env::args().collect();
    let _ = args_list.pop_front();

    let mut layout: Option<PathBuf> = None;
    let mut memory_layout: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;

    while let Some(cur) = args_list.pop_front() {
        match cur.as_str() {
            LAYOUT => {
                if layout.is_some() {
                    eprintln!("{LAYOUT} is specified more than once!");
                    return None;
                } else if let Some(path) = args_list.pop_front() {
                    layout = Some(PathBuf::from(path));
                } else {
                    eprintln!("Parameter to {LAYOUT} is missing!");
                    return None;
                }
            }
            MEMORY_LAYOUT => {
                if memory_layout.is_some() {
                    eprintln!("{MEMORY_LAYOUT} is specified more than once!");
                    return None;
                } else if let Some(path) = args_list.pop_front() {
                    memory_layout = Some(PathBuf::from(path));
                } else {
                    eprintln!("Parameter to {MEMORY_LAYOUT} is missing!");
                    return None;
                }
            }
            OUTPUT => {
                if output.is_some() {
                    eprintln!("{OUTPUT} is specified more than once!");
                    return None;
                } else if let Some(path) = args_list.pop_front() {
                    output = Some(PathBuf::from(path));
                } else {
                    eprintln!("Parameter to {OUTPUT} is missing!");
                    return None;
                }
            }
            _ => {
                eprintln!("Unknown argument: {cur}");
                return None;
            }
        }
    }

    if layout.is_none() {
        eprintln!("{LAYOUT} is required!");
        return None;
    }
    if output.is_none() {
        eprintln!("{OUTPUT} is required!");
        return None;
    }

    Some(Args {
        layout: layout.unwrap(),
        memory_layout,
        output: output.unwrap(),
    })
}

fn main() {
    if let Some(args) = prepare_args() {
        let mem_config = if let Some(path) = &args.memory_layout {
            parse_memory_layout(path).unwrap_or_else(|e| {
                eprintln!("Error parsing memory layout: {e:?}");
                std::process::exit(1);
            })
        } else {
            MemoryLayoutConfig {
                perm_mem: Vec::new(),
                temp_mem: Vec::new(),
            }
        };
        if let Err(e) = generate_from_layout(&args.layout, &mem_config, &args.output) {
            eprintln!("Error: {e:?}");
            std::process::exit(1);
        }
    } else {
        show_help();
        std::process::exit(1);
    }
}

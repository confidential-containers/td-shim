// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Prints TDX_METADATA (all sections), TD_INFO (if present), and TD_PARAMS
//! (if present) from a td-shim firmware image. Optionally parses the TD_INFO
//! payload using a user-supplied JSON layout descriptor.

use std::convert::TryInto;
use std::path::PathBuf;
use std::process;

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use td_shim_interface::metadata::{
    TdxMetadataSection, TDX_METADATA_SECTION_TYPE_TD_INFO, TDX_METADATA_SECTION_TYPE_TD_PARAMS,
};
use td_shim_tools::image::{Image, ParsedMetadata};

/// TD_INFO generic header size: guid(16) + length(4) + version(4) + svn(4)
const TD_INFO_HEADER_SIZE: usize = 28;

fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return format!("{bytes:02x?}");
    }
    // Standard mixed-endian GUID display
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

fn format_hash(bytes: &[u8]) -> String {
    if bytes.iter().all(|&b| b == 0) {
        return String::from("<zero>");
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A field descriptor for structured TD_INFO payload parsing.
#[derive(Debug)]
struct LayoutField {
    name: String,
    r#type: FieldType,
    /// Number of bytes for "bytes" type (or array syntax like "u8[32]").
    size: Option<usize>,
}

#[derive(Debug)]
enum FieldType {
    U8,
    U16,
    U32,
    U64,
    Bytes,
}

/// Helper for JSON deserialization of LayoutField.
#[derive(Deserialize)]
struct LayoutFieldRaw {
    name: String,
    r#type: String,
    size: Option<usize>,
}

impl<'de> Deserialize<'de> for LayoutField {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = LayoutFieldRaw::deserialize(deserializer)?;
        let (field_type, inferred_size) =
            parse_field_type(&raw.r#type).map_err(serde::de::Error::custom)?;
        // Explicit "size" in JSON takes precedence; otherwise use inferred from array syntax
        let size = raw.size.or(inferred_size);
        Ok(LayoutField {
            name: raw.name,
            r#type: field_type,
            size,
        })
    }
}

fn parse_field_type(s: &str) -> std::result::Result<(FieldType, Option<usize>), String> {
    match s {
        "u8" => Ok((FieldType::U8, None)),
        "u16" => Ok((FieldType::U16, None)),
        "u32" => Ok((FieldType::U32, None)),
        "u64" => Ok((FieldType::U64, None)),
        "bytes" => Ok((FieldType::Bytes, None)),
        other => {
            // Support array syntax: "u8[N]", "u16[N]", etc. → Bytes with computed size
            if let Some(bracket) = other.find('[') {
                let base = &other[..bracket];
                let count_str = other[bracket + 1..].trim_end_matches(']');
                let elem_size = match base {
                    "u8" => Some(1usize),
                    "u16" => Some(2usize),
                    "u32" => Some(4usize),
                    "u64" => Some(8usize),
                    _ => None,
                };
                if let (Some(esz), Ok(count)) = (elem_size, count_str.parse::<usize>()) {
                    return Ok((FieldType::Bytes, Some(esz * count)));
                }
            }
            Err(format!(
                "unknown type \"{other}\", expected: u8, u16, u32, u64, bytes, or array syntax (e.g. u8[32])"
            ))
        }
    }
}

fn print_payload_with_layout(payload: &[u8], layout: &[LayoutField]) {
    let mut pos = 0usize;
    for field in layout {
        let remaining = payload.len() - pos;
        match field.r#type {
            FieldType::U8 => {
                if remaining < 1 {
                    println!("  {:<20}: <truncated>", field.name);
                    return;
                }
                let val = payload[pos];
                println!("  {:<20}: {val} (0x{val:02X})", field.name);
                pos += 1;
            }
            FieldType::U16 => {
                if remaining < 2 {
                    println!("  {:<20}: <truncated>", field.name);
                    return;
                }
                let val = u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap());
                println!("  {:<20}: {val} (0x{val:04X})", field.name);
                pos += 2;
            }
            FieldType::U32 => {
                if remaining < 4 {
                    println!("  {:<20}: <truncated>", field.name);
                    return;
                }
                let val = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
                println!("  {:<20}: {val} (0x{val:08X})", field.name);
                pos += 4;
            }
            FieldType::U64 => {
                if remaining < 8 {
                    println!("  {:<20}: <truncated>", field.name);
                    return;
                }
                let val = u64::from_le_bytes(payload[pos..pos + 8].try_into().unwrap());
                println!("  {:<20}: {val} (0x{val:016X})", field.name);
                pos += 8;
            }
            FieldType::Bytes => {
                let size = field.size.unwrap_or(0);
                if remaining < size {
                    println!("  {:<20}: <truncated>", field.name);
                    return;
                }
                let val = &payload[pos..pos + size];
                println!("  {:<20}: {}", field.name, format_hash(val));
                pos += size;
            }
        }
    }
    if pos < payload.len() {
        println!("  {:<20}: {} bytes", "<remaining>", payload.len() - pos);
    }
}

/// Wrapper to support both `[...]` (plain array) and `{"fields": [...]}` (object) formats.
#[derive(Debug, Deserialize)]
struct LayoutWrapper {
    fields: Vec<LayoutField>,
}

fn parse_layout(content: &str) -> serde_json::Result<Vec<LayoutField>> {
    // Try as array first, then as object with "fields" key
    serde_json::from_str::<Vec<LayoutField>>(content)
        .or_else(|_| serde_json::from_str::<LayoutWrapper>(content).map(|w| w.fields))
}

fn print_metadata(meta: &ParsedMetadata) {
    println!("=== TDX Metadata ===");
    println!("  GUID     : {}", format_guid(&meta.guid));
    println!("  Version  : {}", meta.descriptor.version);
    println!("  Sections : {}", meta.descriptor.number_of_section_entry);

    for (i, section) in meta.sections.iter().enumerate() {
        let type_name = TdxMetadataSection::get_type_name(section.r#type)
            .unwrap_or_else(|| format!("Unknown({})", section.r#type));
        println!();
        println!("  [{i}] {type_name}");
        println!("      Data Offset    : 0x{:08X}", section.data_offset);
        println!("      Raw Data Size  : 0x{:08X}", section.raw_data_size);
        println!("      Memory Address : 0x{:016X}", section.memory_address);
        println!("      Memory Size    : 0x{:016X}", section.memory_data_size);
        println!("      Attributes     : 0x{:08X}", section.attributes);
    }
}

fn xxd_dump(data: &[u8], base_offset: usize, indent: &str) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = base_offset + i * 16;
        print!("{indent}{offset:08x}: ");
        for (j, b) in chunk.iter().enumerate() {
            print!("{b:02x}");
            if j % 2 == 1 {
                print!(" ");
            }
        }
        // Pad if last line is short
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                print!("  ");
                if j % 2 == 1 {
                    print!(" ");
                }
            }
        }
        print!(" ");
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            };
            print!("{c}");
        }
        println!();
    }
}

fn print_td_info(
    image: &Image,
    meta: &ParsedMetadata,
    dump_payload: bool,
    layout: Option<&[LayoutField]>,
) {
    let section = match meta.find_section(TDX_METADATA_SECTION_TYPE_TD_INFO) {
        Some(s) => s,
        None => {
            println!("\n=== TD_INFO: not present ===");
            return;
        }
    };

    let offset = section.data_offset as usize;
    let size = section.raw_data_size as usize;

    if offset + size > image.binary.len() {
        println!("\n=== TD_INFO: section extends beyond image bounds ===");
        return;
    }

    if size < TD_INFO_HEADER_SIZE {
        println!("\n=== TD_INFO: section too small ({size} < {TD_INFO_HEADER_SIZE}) ===");
        return;
    }

    let data = &image.binary[offset..offset + size];

    if data.iter().all(|&b| b == 0) {
        println!("\n=== TD_INFO: present but empty (not patched) ===");
        return;
    }

    let guid = &data[0..16];
    let length = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let version = u32::from_le_bytes(data[20..24].try_into().unwrap());
    let svn = u32::from_le_bytes(data[24..28].try_into().unwrap());

    let major = (version >> 24) & 0xFF;
    let minor = (version >> 16) & 0xFF;
    let patch = version & 0xFFFF;

    println!("\n=== TD_INFO ===");
    println!("  GUID         : {}", format_guid(guid));
    println!("  Length       : {length} bytes");
    println!("  Version      : {major}.{minor}.{patch}");
    println!("  SVN          : {svn}");

    let payload_size = (length as usize).saturating_sub(TD_INFO_HEADER_SIZE);
    if payload_size > 0 && TD_INFO_HEADER_SIZE + payload_size <= size {
        let payload = &data[TD_INFO_HEADER_SIZE..TD_INFO_HEADER_SIZE + payload_size];
        println!("  Payload      : {payload_size} bytes");
        if let Some(fields) = layout {
            println!();
            print_payload_with_layout(payload, fields);
        } else if dump_payload {
            println!();
            xxd_dump(payload, offset + TD_INFO_HEADER_SIZE, "  ");
        } else {
            let display_len = payload_size.min(64);
            print!("  Payload (hex): ");
            for b in &payload[..display_len] {
                print!("{b:02x}");
            }
            if payload_size > display_len {
                print!("...");
            }
            println!();
        }
    }
}

/// TD_PARAMS is exactly 1024 bytes (TDX Module spec).
const TD_PARAMS_SIZE: usize = 1024;

fn print_td_params(image: &Image, meta: &ParsedMetadata) {
    let section = match meta.find_section(TDX_METADATA_SECTION_TYPE_TD_PARAMS) {
        Some(s) => s,
        None => {
            println!("\n=== TD_PARAMS: not present ===");
            return;
        }
    };

    let offset = section.data_offset as usize;
    let size = section.raw_data_size as usize;

    if offset + size > image.binary.len() {
        println!("\n=== TD_PARAMS: section extends beyond image bounds ===");
        return;
    }

    if size < TD_PARAMS_SIZE {
        println!("\n=== TD_PARAMS: section too small ({size} < {TD_PARAMS_SIZE}) ===");
        return;
    }

    let data = &image.binary[offset..offset + TD_PARAMS_SIZE];

    if data.iter().all(|&b| b == 0) {
        println!("\n=== TD_PARAMS: present but empty (not patched) ===");
        return;
    }

    // Parse fields per TDX Module spec layout
    let mut pos = 0usize;

    let attributes = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let xfam = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let max_vcpus = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_l2_vms = data[pos];
    pos += 1;
    let msr_config_ctls = data[pos];
    pos += 1;
    let _reserved = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let eptp_controls = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let config_flags = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let tsc_frequency = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    // reserved2: 38 bytes
    pos += 38;
    let mr_config_id = &data[pos..pos + 48];
    pos += 48;
    let mr_owner = &data[pos..pos + 48];
    pos += 48;
    let mr_owner_config = &data[pos..pos + 48];
    pos += 48;
    let ia32_arch_cap_config = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let mr_config_svn = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let mr_owner_config_svn = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());

    println!("\n=== TD_PARAMS ===");
    println!("  Attributes       : 0x{attributes:016X}");
    println!("  XFAM             : 0x{xfam:016X}");
    println!("  Max VCPUs        : {max_vcpus}");
    println!("  Num L2 VMs       : {num_l2_vms}");
    println!("  MSR Config Ctls  : 0x{msr_config_ctls:02X}");
    println!("  EPTP Controls    : 0x{eptp_controls:016X}");
    println!("  Config Flags     : 0x{config_flags:016X}");
    println!("  TSC Frequency    : {tsc_frequency}");
    println!("  MR Config ID     : {}", format_hash(mr_config_id));
    println!("  MR Owner         : {}", format_hash(mr_owner));
    println!("  MR Owner Config  : {}", format_hash(mr_owner_config));
    println!("  IA32 Arch Cap    : 0x{ia32_arch_cap_config:016X}");
    println!("  MR Config SVN    : {mr_config_svn}");
    println!("  MR Owner Cfg SVN : {mr_owner_config_svn}");
}

fn usage(program: &str) {
    eprintln!("Usage: {program} [OPTIONS] <td-shim-image>");
    eprintln!();
    eprintln!("Print TDX_METADATA, TD_INFO, and TD_PARAMS from a td-shim firmware image.");
    eprintln!();
    eprintln!("Options:");
    eprintln!(
        "  -d, --dump-td-info-payload            Print full TD_INFO payload as xxd-style hex dump"
    );
    eprintln!(
        "  -l, --td-info-payload-layout <json>   Parse TD_INFO payload using a JSON layout file"
    );
    eprintln!("  -V, --version                         Print version and exit");
    eprintln!("  -h, --help                            Show this help message and exit");
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut dump_payload = false;
    let mut layout_path: Option<PathBuf> = None;
    let mut positional: Vec<&str> = Vec::new();
    let mut iter = args[1..].iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                usage(&args[0]);
                process::exit(0);
            }
            "-V" | "--version" => {
                eprintln!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            "-d" | "--dump-td-info-payload" => dump_payload = true,
            "-l" | "--td-info-payload-layout" => {
                let path = iter.next().unwrap_or_else(|| {
                    eprintln!("--td-info-payload-layout requires a path argument");
                    usage(&args[0]);
                    process::exit(1);
                });
                layout_path = Some(PathBuf::from(path));
            }
            s if s.starts_with('-') => {
                eprintln!("Unknown option: {s}");
                usage(&args[0]);
                process::exit(1);
            }
            s => positional.push(s),
        }
    }

    if positional.len() != 1 {
        usage(&args[0]);
        process::exit(1);
    }

    let layout: Option<Vec<LayoutField>> = match &layout_path {
        Some(p) => {
            let content = std::fs::read_to_string(p)
                .with_context(|| format!("failed to read layout file: {}", p.display()))?;
            let fields = parse_layout(&content)
                .with_context(|| format!("failed to parse layout JSON: {}", p.display()))?;
            ensure!(!fields.is_empty(), "layout file contains no fields");
            Some(fields)
        }
        None => None,
    };

    let path = PathBuf::from(positional[0]);
    let image =
        Image::open(&path).with_context(|| format!("failed to open image: {}", path.display()))?;
    let meta =
        ParsedMetadata::from_image(&image).context("failed to parse TDX metadata from image")?;

    print_metadata(&meta);
    print_td_info(&image, &meta, dump_payload, layout.as_deref());
    print_td_params(&image, &meta);

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:?}");
        process::exit(1);
    }
}

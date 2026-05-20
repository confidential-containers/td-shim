// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Image Layout Generator
//!
//! Computes a td-shim image layout by reading a JSON template, measuring the
//! actual sizes of built artifacts (payload, IPL, reset vector), accounting for
//! firmware volume (FV) header overhead, and producing a generated layout JSON
//! with 4 KiB-aligned section sizes.
//!
//! The generated JSON can be consumed by `td-layout-config` to regenerate
//! build-time constants, or by `td-shim-ld` directly.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

// Command-line argument names
const PROJECT_ROOT: &str = "--project-root";
const CARGO_TARGET_DIR: &str = "--cargo-target-dir";
const BUILD_TARGET: &str = "--build-target";
const CARGO_BUILD_DIRECTORY: &str = "--cargo-build-directory";
const PAYLOAD_BINARY: &str = "--payload-binary";
const IPL_BINARY: &str = "--ipl-binary";
const RESET_VECTOR_BINARY: &str = "--reset-vector-binary";
const OUTPUT: &str = "--output";
const TEMPLATE: &str = "--template";

const ALIGN_4K: u64 = 0x1000;
const DEFAULT_LAYOUT: &str = r#"{
    "TdParams": "0x1000",
    "TempStack": "0x20000",
    "TempHeap": "0x20000",
    "Payload": "0x140000",
    "TdInfo": "0x1000",
    "Metadata": "0x1000",
    "Ipl": "0x2e000",
    "ResetVector": "0x8000"
}"#;

#[derive(Debug)]
pub struct Args {
    pub project_root: PathBuf,
    pub cargo_target_dir: String,
    pub build_target: String,
    pub cargo_build_directory: String,
    pub payload_binary: String,
    pub ipl_binary: String,
    pub reset_vector_binary: String,
    pub output: Option<PathBuf>,
    pub template: Option<PathBuf>,
}

#[derive(Clone, Deserialize, Serialize)]
struct ImageLayout {
    #[serde(rename = "Config", default, skip_serializing_if = "Option::is_none")]
    config: Option<String>,
    #[serde(rename = "Mailbox", default, skip_serializing_if = "Option::is_none")]
    mailbox: Option<String>,
    #[serde(rename = "TempStack")]
    temp_stack: String,
    #[serde(rename = "TempHeap")]
    temp_heap: String,
    #[serde(rename = "Payload")]
    payload: String,
    #[serde(rename = "TdInfo", default, skip_serializing_if = "Option::is_none")]
    td_info: Option<String>,
    #[serde(rename = "TdParams", default, skip_serializing_if = "Option::is_none")]
    td_params: Option<String>,
    #[serde(rename = "Metadata")]
    metadata: String,
    #[serde(rename = "Ipl")]
    ipl: String,
    #[serde(rename = "ResetVector")]
    reset_vector: String,
    #[serde(rename = "ImageSize", default, skip_serializing_if = "Option::is_none")]
    image_size: Option<String>,
}

fn generate_image_layout(args: Args) -> Result<()> {
    let template_content = if let Some(template_path) = &args.template {
        std::fs::read_to_string(template_path)
            .with_context(|| format!("failed to read template from {}", template_path.display()))?
    } else {
        DEFAULT_LAYOUT.to_string()
    };

    let mut layout: ImageLayout = serde_json::from_str(&template_content)
        .with_context(|| "failed to deserialize image layout template")?;

    let target_dir = resolve_target_dir(&args.project_root, &args.cargo_target_dir);
    let payload_path = artifact_path(
        &target_dir,
        &[
            &args.build_target,
            &args.cargo_build_directory,
            &args.payload_binary,
        ],
    );

    // For the IPL and reset vector, check if the requested build directory
    // exists; fall back to release if not.
    let ipl_build_dir = cargo_build_directory_with_fallback(
        &args.cargo_build_directory,
        &target_dir,
        "x86_64-unknown-none",
        &args.ipl_binary,
    );
    let ipl_path = artifact_path(
        &target_dir,
        &["x86_64-unknown-none", &ipl_build_dir, &args.ipl_binary],
    );
    let reset_vector_path = artifact_path(
        &target_dir,
        &[
            "x86_64-unknown-none",
            &ipl_build_dir,
            &args.reset_vector_binary,
        ],
    );

    // Account for FV headers that td-shim adds to the payload section.
    // FvHeader + FvFfsFileHeader + FvFfsSectionHeader ≈ 148 bytes, rounded up.
    const FV_HEADER_OVERHEAD: u64 = 256;

    // Account for FV + reset vector headers that td-shim adds to the IPL section.
    // IplFvHeaderByte (~148 bytes) + ResetVectorHeader (~40 bytes) ≈ 188 bytes.
    const IPL_HEADER_OVERHEAD: u64 = 256;

    let payload_binary_size = file_size(&payload_path)?;
    let payload_size = align_up(payload_binary_size + FV_HEADER_OVERHEAD, ALIGN_4K);

    // The linker checks both the file size and the ELF virtual address extent
    // against MAX_IPL_CONTENT_SIZE. Use the larger of the two.
    let ipl_file_size = file_size(&ipl_path)?;
    let ipl_vaddr_extent = elf64_max_vaddr_filesz(&ipl_path)?;
    let ipl_size = align_up(
        ipl_file_size.max(ipl_vaddr_extent) + IPL_HEADER_OVERHEAD,
        ALIGN_4K,
    );
    let reset_vector_size = align_up(file_size(&reset_vector_path)?, ALIGN_4K);

    println!(
        "Payload binary size: {} ({})",
        format_size(payload_binary_size),
        payload_binary_size
    );
    println!(
        "Payload section size (with headers): {} ({})",
        format_size(payload_size),
        payload_size
    );

    let original_payload = parse_size(&layout.payload)?;
    let original_ipl = parse_size(&layout.ipl)?;

    layout.payload = format_size(payload_size);
    layout.ipl = format_size(ipl_size);
    layout.reset_vector = format_size(reset_vector_size);

    let config_size = parse_optional(&layout.config)?;
    let mailbox_size = parse_optional(&layout.mailbox)?;
    let temp_stack = parse_size(&layout.temp_stack)?;
    let temp_heap = parse_size(&layout.temp_heap)?;
    let td_params = parse_optional(&layout.td_params)?;
    let td_info = parse_optional(&layout.td_info)?;
    let metadata = parse_size(&layout.metadata)?;

    let mut new_image_size = config_size
        + mailbox_size
        + temp_stack
        + temp_heap
        + payload_size
        + td_params
        + td_info
        + metadata
        + ipl_size
        + reset_vector_size;
    new_image_size = align_up(new_image_size, ALIGN_4K);

    if let Some(original) = layout
        .image_size
        .as_ref()
        .map(|value| parse_size(value))
        .transpose()?
    {
        // Preserve growth beyond computed minimum if template carried extra padding.
        let baseline = original
            .saturating_sub(original_payload)
            .saturating_sub(original_ipl);
        new_image_size = align_up(baseline + payload_size + ipl_size, ALIGN_4K).max(new_image_size);
    }

    layout.image_size = Some(format_size(new_image_size));

    let generated_dir = args.project_root.join("target").join("config");
    std::fs::create_dir_all(&generated_dir).with_context(|| {
        format!(
            "failed to create directory for generated layout: {}",
            generated_dir.display()
        )
    })?;
    let generated_layout = generated_dir.join("image_layout.generated.json");
    let serialized = serde_json::to_string_pretty(&layout)?;
    std::fs::write(&generated_layout, &serialized).with_context(|| {
        format!(
            "failed to write generated layout to {}",
            generated_layout.display()
        )
    })?;

    if let Some(output) = args.output {
        std::fs::copy(&generated_layout, &output)
            .with_context(|| format!("failed to copy generated layout to {}", output.display()))?;
        println!("Image layout generated and copied to: {}", output.display());
    } else {
        println!("Image layout generated at: {}", generated_layout.display());
    }

    Ok(())
}

fn show_help() {
    println!("td-shim-image-layout-gen {VERSION}");
    println!();
    println!("Computes a td-shim image layout from built artifacts.");
    println!();
    println!("Usage:");
    println!("    {PROJECT_ROOT} <path>              Root directory of the project (required).");
    println!("    {CARGO_TARGET_DIR} <dir>           Cargo target directory (default: target/).");
    println!("    {BUILD_TARGET} <target>            Build target triple (default: x86_64-unknown-none).");
    println!("    {CARGO_BUILD_DIRECTORY} <dir>      Build profile directory (default: release).");
    println!("    {PAYLOAD_BINARY} <name>            Payload binary name (required).");
    println!("    {IPL_BINARY} <name>                IPL binary name (default: td-shim).");
    println!("    {RESET_VECTOR_BINARY} <name>       Reset vector binary name (default: ResetVector.bin).");
    println!("    {TEMPLATE} <path>                  Layout template JSON (optional, uses built-in default).");
    println!("    {OUTPUT} <path>                    Output file path (optional).");
}

fn prepare_args() -> Option<Args> {
    use std::collections::VecDeque;
    use std::env;
    let mut args_list: VecDeque<String> = env::args().collect();
    let _ = args_list.pop_front();

    let mut project_root: Option<PathBuf> = None;
    let mut cargo_target_dir: Option<String> = None;
    let mut build_target: Option<String> = None;
    let mut cargo_build_directory: Option<String> = None;
    let mut payload_binary: Option<String> = None;
    let mut ipl_binary: Option<String> = None;
    let mut reset_vector_binary: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut template: Option<PathBuf> = None;

    while let Some(cur) = args_list.pop_front() {
        match cur.as_str() {
            PROJECT_ROOT => {
                if project_root.is_some() {
                    eprintln!("{PROJECT_ROOT} is specified more than once!");
                    return None;
                } else if let Some(path) = args_list.pop_front() {
                    project_root = Some(PathBuf::from(path));
                } else {
                    eprintln!("Parameter to {PROJECT_ROOT} is missing!");
                    return None;
                }
            }
            CARGO_TARGET_DIR => {
                if cargo_target_dir.is_some() {
                    eprintln!("{CARGO_TARGET_DIR} is specified more than once!");
                    return None;
                } else if let Some(dir) = args_list.pop_front() {
                    cargo_target_dir = Some(dir);
                } else {
                    eprintln!("Parameter to {CARGO_TARGET_DIR} is missing!");
                    return None;
                }
            }
            BUILD_TARGET => {
                if build_target.is_some() {
                    eprintln!("{BUILD_TARGET} is specified more than once!");
                    return None;
                } else if let Some(target) = args_list.pop_front() {
                    build_target = Some(target);
                } else {
                    eprintln!("Parameter to {BUILD_TARGET} is missing!");
                    return None;
                }
            }
            CARGO_BUILD_DIRECTORY => {
                if cargo_build_directory.is_some() {
                    eprintln!("{CARGO_BUILD_DIRECTORY} is specified more than once!");
                    return None;
                } else if let Some(dir) = args_list.pop_front() {
                    cargo_build_directory = Some(dir);
                } else {
                    eprintln!("Parameter to {CARGO_BUILD_DIRECTORY} is missing!");
                    return None;
                }
            }
            PAYLOAD_BINARY => {
                if payload_binary.is_some() {
                    eprintln!("{PAYLOAD_BINARY} is specified more than once!");
                    return None;
                } else if let Some(name) = args_list.pop_front() {
                    payload_binary = Some(name);
                } else {
                    eprintln!("Parameter to {PAYLOAD_BINARY} is missing!");
                    return None;
                }
            }
            IPL_BINARY => {
                if ipl_binary.is_some() {
                    eprintln!("{IPL_BINARY} is specified more than once!");
                    return None;
                } else if let Some(name) = args_list.pop_front() {
                    ipl_binary = Some(name);
                } else {
                    eprintln!("Parameter to {IPL_BINARY} is missing!");
                    return None;
                }
            }
            RESET_VECTOR_BINARY => {
                if reset_vector_binary.is_some() {
                    eprintln!("{RESET_VECTOR_BINARY} is specified more than once!");
                    return None;
                } else if let Some(name) = args_list.pop_front() {
                    reset_vector_binary = Some(name);
                } else {
                    eprintln!("Parameter to {RESET_VECTOR_BINARY} is missing!");
                    return None;
                }
            }
            TEMPLATE => {
                if template.is_some() {
                    eprintln!("{TEMPLATE} is specified more than once!");
                    return None;
                } else if let Some(path) = args_list.pop_front() {
                    template = Some(PathBuf::from(path));
                } else {
                    eprintln!("Parameter to {TEMPLATE} is missing!");
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

    if project_root.is_none() {
        eprintln!("{PROJECT_ROOT} is required!");
        return None;
    }
    if payload_binary.is_none() {
        eprintln!("{PAYLOAD_BINARY} is required!");
        return None;
    }

    Some(Args {
        project_root: project_root.unwrap(),
        cargo_target_dir: cargo_target_dir.unwrap_or_default(),
        build_target: build_target.unwrap_or_else(|| "x86_64-unknown-none".to_string()),
        cargo_build_directory: cargo_build_directory.unwrap_or_else(|| "release".to_string()),
        payload_binary: payload_binary.unwrap(),
        ipl_binary: ipl_binary.unwrap_or_else(|| "td-shim".to_string()),
        reset_vector_binary: reset_vector_binary.unwrap_or_else(|| "ResetVector.bin".to_string()),
        output,
        template,
    })
}

fn main() {
    if let Some(args) = prepare_args() {
        if let Err(e) = generate_image_layout(args) {
            eprintln!("Error: {e:?}");
            std::process::exit(1);
        }
    } else {
        show_help();
        std::process::exit(1);
    }
}

fn resolve_target_dir(project_root: &Path, cargo_target_dir: &str) -> PathBuf {
    let mut target_dir = if cargo_target_dir.is_empty() {
        project_root.join("target")
    } else {
        PathBuf::from(cargo_target_dir)
    };

    if target_dir.is_relative() {
        target_dir = project_root.join(target_dir);
    }

    target_dir
}

fn cargo_build_directory_with_fallback(
    dir: &str,
    target_dir: &Path,
    target_arch: &str,
    binary_name: &str,
) -> String {
    if dir.is_empty() {
        "release".to_string()
    } else {
        let binary_path = target_dir.join(target_arch).join(dir).join(binary_name);
        if binary_path.exists() {
            dir.to_string()
        } else {
            "release".to_string()
        }
    }
}

fn artifact_path(base: &Path, components: &[&str]) -> PathBuf {
    components
        .iter()
        .fold(base.to_path_buf(), |acc, &c| acc.join(c))
}

fn file_size(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("failed to get metadata for {}", path.display()))?
        .len())
}

fn parse_optional(value: &Option<String>) -> Result<u64> {
    value.as_ref().map(|s| parse_size(s)).unwrap_or(Ok(0))
}

fn parse_size(value: &str) -> Result<u64> {
    if let Some(stripped) = value.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16)
            .map_err(|err| anyhow::anyhow!("invalid hex value '{}': {err}", value))
    } else {
        value
            .parse::<u64>()
            .map_err(|err| anyhow::anyhow!("invalid numeric value '{}': {err}", value))
    }
}

fn format_size(value: u64) -> String {
    format!("0x{value:x}")
}

fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value.div_ceil(align) * align
}

/// Read an ELF64 binary and return the maximum (p_vaddr + p_filesz) across all
/// PT_LOAD program headers. This represents the virtual address extent that the
/// td-shim linker's relocation buffer must accommodate.
fn elf64_max_vaddr_filesz(path: &Path) -> Result<u64> {
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .with_context(|| format!("failed to read {}", path.display()))?;

    anyhow::ensure!(data.len() >= 64, "ELF file too small: {}", path.display());
    anyhow::ensure!(
        &data[0..4] == b"\x7fELF",
        "not a valid ELF file: {}",
        path.display()
    );
    anyhow::ensure!(data[4] == 2, "not a 64-bit ELF file: {}", path.display());

    let is_le = data[5] == 1;
    let read_u16 = |off: usize| -> u16 {
        if is_le {
            u16::from_le_bytes([data[off], data[off + 1]])
        } else {
            u16::from_be_bytes([data[off], data[off + 1]])
        }
    };
    let read_u32 = |off: usize| -> u32 {
        if is_le {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
        } else {
            u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
        }
    };
    let read_u64 = |off: usize| -> u64 {
        if is_le {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
        } else {
            u64::from_be_bytes(data[off..off + 8].try_into().unwrap())
        }
    };

    let e_phoff = read_u64(32) as usize;
    let e_phentsize = read_u16(54) as usize;
    let e_phnum = read_u16(56) as usize;

    // ELF64 program header entry is 56 bytes; reject malformed ELFs early.
    anyhow::ensure!(
        e_phentsize >= 56,
        "invalid e_phentsize {} (expected >= 56) in {}",
        e_phentsize,
        path.display()
    );

    const PT_LOAD: u32 = 1;
    let mut max_extent: u64 = 0;

    for i in 0..e_phnum {
        let ph_off = e_phoff + i * e_phentsize;
        anyhow::ensure!(
            ph_off + e_phentsize <= data.len(),
            "program header out of bounds in {}",
            path.display()
        );
        let p_type = read_u32(ph_off);
        if p_type == PT_LOAD {
            let p_vaddr = read_u64(ph_off + 16);
            let p_filesz = read_u64(ph_off + 32);
            let extent = p_vaddr
                .checked_add(p_filesz)
                .with_context(|| format!("overflow in ELF program header in {}", path.display()))?;
            if extent > max_extent {
                max_extent = extent;
            }
        }
    }

    anyhow::ensure!(
        max_extent > 0,
        "no PT_LOAD segments found in {}",
        path.display()
    );
    Ok(max_extent)
}

// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Integration tests for td-shim-patch binary.
//!
//! These tests build synthetic firmware images with valid TDX metadata
//! and exercise each subcommand.

use std::path::PathBuf;
use std::process::Command;

use scroll::Pwrite;

fn bin_path() -> PathBuf {
    let mut path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push("td-shim-patch");
    path
}

// -- Constants matching td-shim-interface/src/metadata.rs --

const TDX_METADATA_OFFSET: u32 = 0x20;
const TDX_METADATA_GUID: [u8; 16] = [
    0xf3, 0xf9, 0xea, 0xe9, // data1 LE
    0x8e, 0x16, // data2 LE
    0xd5, 0x44, // data3 LE
    0xa8, 0xeb, 0x7f, 0x4d, 0x87, 0x38, 0xf6, 0xae, // data4 BE
];

const TDX_METADATA_SIGNATURE: u32 = 0x46564454; // 'TDVF'
const TDX_METADATA_SECTION_TYPE_TD_INFO: u32 = 7;
const TDX_METADATA_SECTION_TYPE_TD_PARAMS: u32 = 8;

/// Build a synthetic firmware image with TDX metadata containing two sections:
/// TD_INFO and TD_PARAMS.
///
/// Layout (from start to end):
/// [0x0000 .. 0x0400)  TD_INFO data region  (1024 bytes)
/// [0x0400 .. 0x0800)  TD_PARAMS data region (1024 bytes)
/// [0x0800 .. end)     padding + metadata structures at end
///
/// Image size: 4096 bytes (one page, easy to reason about).
fn build_test_image() -> Vec<u8> {
    let image_size: usize = 4096;
    let mut image = vec![0u8; image_size];

    // Section data regions
    let td_info_offset: u32 = 0x0000;
    let td_info_size: u32 = 1024;
    let td_params_offset: u32 = 0x0400;
    let td_params_size: u32 = 1024;

    // We'll place metadata at a known position near the end.
    // Metadata pointer is at: image_size - TDX_METADATA_OFFSET (= 4096 - 32 = 4064)
    // Metadata layout (from descriptor start going forward):
    //   GUID (16 bytes) | Descriptor (16 bytes) | Section0 (32 bytes) | Section1 (32 bytes)
    // Total metadata block = 16 + 16 + 64 = 96 bytes
    // Let descriptor start at offset 3952 (which leaves room: 3952 + 16 + 64 = 4032, < 4064)

    let descriptor_offset: usize = 3952;
    let guid_offset = descriptor_offset - 16;

    // Write GUID
    image[guid_offset..guid_offset + 16].copy_from_slice(&TDX_METADATA_GUID);

    // Write descriptor: signature(4) + length(4) + version(4) + num_sections(4)
    let num_sections: u32 = 2;
    let descriptor_length: u32 = 16 + num_sections * 32; // 80
    image
        .pwrite_with(TDX_METADATA_SIGNATURE, descriptor_offset, scroll::LE)
        .unwrap();
    image
        .pwrite_with(descriptor_length, descriptor_offset + 4, scroll::LE)
        .unwrap();
    image
        .pwrite_with(1u32, descriptor_offset + 8, scroll::LE)
        .unwrap(); // version
    image
        .pwrite_with(num_sections, descriptor_offset + 12, scroll::LE)
        .unwrap();

    // Write sections (each 32 bytes): data_offset(4) + raw_data_size(4) +
    //   memory_address(8) + memory_data_size(8) + type(4) + attributes(4)
    let sections_start = descriptor_offset + 16;

    // Section 0: TD_INFO
    let s0 = sections_start;
    image.pwrite_with(td_info_offset, s0, scroll::LE).unwrap();
    image.pwrite_with(td_info_size, s0 + 4, scroll::LE).unwrap();
    image
        .pwrite_with(0x1000_0000u64, s0 + 8, scroll::LE)
        .unwrap(); // memory_address
    image
        .pwrite_with(td_info_size as u64, s0 + 16, scroll::LE)
        .unwrap(); // memory_data_size
    image
        .pwrite_with(TDX_METADATA_SECTION_TYPE_TD_INFO, s0 + 24, scroll::LE)
        .unwrap();
    image.pwrite_with(0x01u32, s0 + 28, scroll::LE).unwrap(); // attributes (non-zero to test zeroing)

    // Section 1: TD_PARAMS
    let s1 = sections_start + 32;
    image.pwrite_with(td_params_offset, s1, scroll::LE).unwrap();
    image
        .pwrite_with(td_params_size, s1 + 4, scroll::LE)
        .unwrap();
    image
        .pwrite_with(0x2000_0000u64, s1 + 8, scroll::LE)
        .unwrap();
    image
        .pwrite_with(td_params_size as u64, s1 + 16, scroll::LE)
        .unwrap();
    image
        .pwrite_with(TDX_METADATA_SECTION_TYPE_TD_PARAMS, s1 + 24, scroll::LE)
        .unwrap();
    image.pwrite_with(0x03u32, s1 + 28, scroll::LE).unwrap(); // attributes

    // Write metadata pointer at (image_size - TDX_METADATA_OFFSET)
    let ptr_offset = image_size - TDX_METADATA_OFFSET as usize;
    image
        .pwrite_with(descriptor_offset as u32, ptr_offset, scroll::LE)
        .unwrap();

    image
}

// ============================================================
// Subcommand: metadata
// ============================================================

#[test]
fn test_patch_metadata_missing_args() {
    let output = Command::new(bin_path())
        .args(["tdx-metadata"])
        .output()
        .expect("failed to run td-shim-patch");

    assert!(!output.status.success());
}

#[test]
fn test_patch_metadata_patches_signature_and_zeros_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("input.bin");
    let output_path = dir.path().join("output.bin");

    std::fs::write(&input_path, build_test_image()).unwrap();

    let new_sig: u32 = 0x58524e5f; // "_NRX"

    let status = Command::new(bin_path())
        .args([
            "tdx-metadata",
            "--in",
            input_path.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
            "--signature",
            "0x58524e5f",
        ])
        .status()
        .expect("failed to run td-shim-patch tdx-metadata");

    assert!(
        status.success(),
        "td-shim-patch tdx-metadata should succeed"
    );
    assert!(output_path.exists());

    // Verify the output image
    let patched = std::fs::read(&output_path).unwrap();
    let descriptor_offset: usize = 3952;
    let sections_start = descriptor_offset + 16;

    // Check signature was patched
    let sig: u32 = scroll::Pread::pread_with(&patched[..], descriptor_offset, scroll::LE).unwrap();
    assert_eq!(sig, new_sig, "signature should be patched to 0x58524e5f");

    // Check section attributes were zeroed
    let attr0: u32 =
        scroll::Pread::pread_with(&patched[..], sections_start + 28, scroll::LE).unwrap();
    let attr1: u32 =
        scroll::Pread::pread_with(&patched[..], sections_start + 32 + 28, scroll::LE).unwrap();
    assert_eq!(attr0, 0, "section 0 attributes should be zeroed");
    assert_eq!(attr1, 0, "section 1 attributes should be zeroed");
}

#[test]
fn test_patch_metadata_invalid_image() {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("bad.bin");
    let output_path = dir.path().join("out.bin");

    // Write an image too small to have metadata
    std::fs::write(&input_path, vec![0u8; 64]).unwrap();

    let status = Command::new(bin_path())
        .args([
            "tdx-metadata",
            "--in",
            input_path.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
            "--signature",
            "0x12345678",
        ])
        .status()
        .expect("failed to run td-shim-patch tdx-metadata");

    assert!(!status.success(), "should fail on invalid image");
}

// ============================================================
// Subcommand: params
// ============================================================

#[test]
fn test_patch_params_missing_args() {
    let output = Command::new(bin_path())
        .args(["td-params"])
        .output()
        .expect("failed to run td-shim-patch");

    assert!(!output.status.success());
}

#[test]
fn test_patch_params_writes_td_params_region() {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("input.bin");
    let output_path = dir.path().join("output.bin");
    let json_path = dir.path().join("td_params.json");

    std::fs::write(&input_path, build_test_image()).unwrap();

    // Write a minimal TD_PARAMS JSON with known values
    let td_params_json = serde_json::json!({
        "attributes": "0x0000000000000001",
        "xfam": "0x0000000000000003",
        "maxvcpus": 8,
        "numl2vms": 0,
        "msrconfigctls": 0
    });
    std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&td_params_json).unwrap(),
    )
    .unwrap();

    let status = Command::new(bin_path())
        .args([
            "td-params",
            "--in",
            input_path.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
            "--tdparams",
            json_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-patch td-params");

    assert!(status.success(), "td-shim-patch td-params should succeed");
    assert!(output_path.exists());

    // Verify the TD_PARAMS region was written
    let patched = std::fs::read(&output_path).unwrap();
    let td_params_offset: usize = 0x0400;

    // attributes (u64 LE) at offset 0 of the region
    let attr: u64 = scroll::Pread::pread_with(&patched[..], td_params_offset, scroll::LE).unwrap();
    assert_eq!(attr, 1, "attributes should be 1");

    // xfam (u64 LE) at offset 8
    let xfam: u64 =
        scroll::Pread::pread_with(&patched[..], td_params_offset + 8, scroll::LE).unwrap();
    assert_eq!(xfam, 3, "xfam should be 3");

    // maxvcpus (u16 LE) at offset 16
    let vcpus: u16 =
        scroll::Pread::pread_with(&patched[..], td_params_offset + 16, scroll::LE).unwrap();
    assert_eq!(vcpus, 8, "maxvcpus should be 8");
}

#[test]
fn test_patch_params_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("input.bin");
    let output_path = dir.path().join("output.bin");
    let json_path = dir.path().join("bad.json");

    std::fs::write(&input_path, build_test_image()).unwrap();
    std::fs::write(&json_path, "not valid json {{{").unwrap();

    let status = Command::new(bin_path())
        .args([
            "td-params",
            "--in",
            input_path.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
            "--tdparams",
            json_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-patch td-params");

    assert!(!status.success(), "should fail on invalid JSON");
}

// ============================================================
// Subcommand: td-info
// ============================================================

#[test]
fn test_patch_td_info_missing_args() {
    let output = Command::new(bin_path())
        .args(["td-info"])
        .output()
        .expect("failed to run td-shim-patch");

    assert!(!output.status.success());
}

#[test]
fn test_patch_td_info_writes_header_and_blob() {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("input.bin");
    let output_path = dir.path().join("output.bin");
    let blob_path = dir.path().join("payload_info.bin");

    std::fs::write(&input_path, build_test_image()).unwrap();

    // Create a small payload blob
    let blob_data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    std::fs::write(&blob_path, &blob_data).unwrap();

    let status = Command::new(bin_path())
        .args([
            "td-info",
            "--in",
            input_path.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
            "--guid",
            "6d8415a6-5701-0247-a696-c0420ce3b4e9",
            "--version",
            "1.2.3",
            "--svn",
            "5",
            "--payload-info",
            blob_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-patch td-info");

    assert!(status.success(), "td-shim-patch td-info should succeed");
    assert!(output_path.exists());

    // Verify the TD_INFO region
    let patched = std::fs::read(&output_path).unwrap();
    let td_info_offset: usize = 0x0000;

    // GUID (16 bytes): 6d8415a6-5701-0247-a696-c0420ce3b4e9 in mixed-endian
    let expected_guid: [u8; 16] = [
        0xa6, 0x15, 0x84, 0x6d, // data1 LE
        0x01, 0x57, // data2 LE
        0x47, 0x02, // data3 LE
        0xa6, 0x96, 0xc0, 0x42, 0x0c, 0xe3, 0xb4, 0xe9, // data4 BE
    ];
    assert_eq!(
        &patched[td_info_offset..td_info_offset + 16],
        &expected_guid,
        "GUID should match"
    );

    // Length (4 bytes LE) at offset 16: header(28) + blob(6) = 34
    let length: u32 =
        scroll::Pread::pread_with(&patched[..], td_info_offset + 16, scroll::LE).unwrap();
    assert_eq!(length, 34, "length should be header + blob size");

    // Version (4 bytes LE) at offset 20: (1<<24) | (2<<16) | 3 = 0x01020003
    let version: u32 =
        scroll::Pread::pread_with(&patched[..], td_info_offset + 20, scroll::LE).unwrap();
    assert_eq!(version, 0x01020003, "version should be 1.2.3 packed");

    // SVN (4 bytes LE) at offset 24
    let svn: u32 =
        scroll::Pread::pread_with(&patched[..], td_info_offset + 24, scroll::LE).unwrap();
    assert_eq!(svn, 5, "svn should be 5");

    // Payload blob at offset 28
    assert_eq!(
        &patched[td_info_offset + 28..td_info_offset + 34],
        &blob_data,
        "payload blob should match"
    );
}

#[test]
fn test_patch_td_info_blob_too_large() {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("input.bin");
    let output_path = dir.path().join("output.bin");
    let blob_path = dir.path().join("huge_blob.bin");

    std::fs::write(&input_path, build_test_image()).unwrap();

    // Create a blob larger than the TD_INFO section (1024 bytes total, minus 28 header = 996 max)
    let blob_data = vec![0xAA; 1024];
    std::fs::write(&blob_path, &blob_data).unwrap();

    let status = Command::new(bin_path())
        .args([
            "td-info",
            "--in",
            input_path.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
            "--guid",
            "6d8415a6-5701-0247-a696-c0420ce3b4e9",
            "--version",
            "1.0.0",
            "--svn",
            "0",
            "--payload-info",
            blob_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-patch td-info");

    assert!(
        !status.success(),
        "should fail when blob exceeds section capacity"
    );
}

// ============================================================
// General / top-level
// ============================================================

#[test]
fn test_patch_no_subcommand() {
    let output = Command::new(bin_path())
        .output()
        .expect("failed to run td-shim-patch");

    assert!(!output.status.success());
}

#[test]
fn test_patch_unknown_subcommand() {
    let output = Command::new(bin_path())
        .args(["bogus"])
        .output()
        .expect("failed to run td-shim-patch");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unknown subcommand"));
}

#[test]
fn test_patch_help() {
    let output = Command::new(bin_path())
        .args(["--help"])
        .output()
        .expect("failed to run td-shim-patch");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tdx-metadata"));
    assert!(stdout.contains("td-params"));
    assert!(stdout.contains("td-info"));
}

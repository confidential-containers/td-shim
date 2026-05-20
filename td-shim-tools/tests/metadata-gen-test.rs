// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Integration tests for td-shim-metadata-gen binary.

use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
    // The integration test binary is built alongside the workspace binaries.
    let mut path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push("td-shim-metadata-gen");
    path
}

/// Create a temporary layout JSON for testing.
fn write_layout(dir: &std::path::Path, content: &str) -> PathBuf {
    let path = dir.join("layout.json");
    std::fs::write(&path, content).unwrap();
    path
}

#[test]
fn test_metadata_gen_with_layout() {
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().join("metadata_output.json");

    let layout = write_layout(
        output_dir.path(),
        r#"{
            "TempStack": "0x20000",
            "TempHeap": "0x20000",
            "Payload": "0x17000",
            "TdInfo": "0x1000",
            "TdParams": "0x1000",
            "Metadata": "0x1000",
            "Ipl": "0x16000",
            "ResetVector": "0x8000",
            "ImageSize": "0x78000"
        }"#,
    );

    let status = Command::new(bin_path())
        .args([
            "--layout",
            layout.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(status.success(), "td-shim-metadata-gen should succeed");
    assert!(output_path.exists(), "output file should be created");

    let content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let sections = parsed["Sections"].as_array().unwrap();
    // Should have: TdParams, BFV, TempMem, Payload, TdInfo
    assert_eq!(sections.len(), 5);
    assert_eq!(sections[0]["Type"], "TdParams");
    assert_eq!(sections[1]["Type"], "BFV");
    assert_eq!(sections[2]["Type"], "TempMem");
    assert_eq!(sections[3]["Type"], "Payload");
    assert_eq!(sections[4]["Type"], "TdInfo");
}

/// Create a temporary memory layout JSON for testing.
fn write_memory_layout(dir: &std::path::Path, content: &str) -> PathBuf {
    let path = dir.join("memory_layout.json");
    std::fs::write(&path, content).unwrap();
    path
}

#[test]
fn test_metadata_gen_with_perm_mem() {
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().join("metadata_output.json");

    let layout = write_layout(
        output_dir.path(),
        r#"{
            "TempStack": "0x20000",
            "TempHeap": "0x20000",
            "Payload": "0x17000",
            "TdInfo": "0x1000",
            "TdParams": "0x1000",
            "Metadata": "0x1000",
            "Ipl": "0x16000",
            "ResetVector": "0x8000",
            "ImageSize": "0x78000"
        }"#,
    );

    let mem_layout = write_memory_layout(
        output_dir.path(),
        r#"{
            "PermMem": [
                { "address": "0x0", "size": "0x2000000" }
            ]
        }"#,
    );

    let status = Command::new(bin_path())
        .args([
            "--layout",
            layout.to_str().unwrap(),
            "--memory-layout",
            mem_layout.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(status.success(), "td-shim-metadata-gen should succeed");

    let content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let sections = parsed["Sections"].as_array().unwrap();
    // Should have: TdParams, BFV, TempMem, Payload, TdInfo, PermMem
    assert_eq!(sections.len(), 6);
    assert_eq!(sections[5]["Type"], "PermMem");
    assert_eq!(sections[5]["Attributes"], "0x2");
    assert_eq!(sections[5]["MemoryAddress"], "0x0");
    assert_eq!(sections[5]["MemoryDataSize"], "0x2000000");
    assert_eq!(sections[5]["DataOffset"], "0x0");
    assert_eq!(sections[5]["RawDataSize"], "0x0");
}

#[test]
fn test_metadata_gen_with_multiple_perm_mem() {
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().join("metadata_output.json");

    let layout = write_layout(
        output_dir.path(),
        r#"{
            "TempStack": "0x20000",
            "TempHeap": "0x20000",
            "Payload": "0x17000",
            "Metadata": "0x1000",
            "Ipl": "0x16000",
            "ResetVector": "0x8000",
            "ImageSize": "0x70000"
        }"#,
    );

    let mem_layout = write_memory_layout(
        output_dir.path(),
        r#"{
            "PermMem": [
                { "address": "0x0", "size": "0x2000000" },
                { "address": "0x100000000", "size": "0x800000000" }
            ]
        }"#,
    );

    let status = Command::new(bin_path())
        .args([
            "--layout",
            layout.to_str().unwrap(),
            "--memory-layout",
            mem_layout.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(status.success());

    let content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let sections = parsed["Sections"].as_array().unwrap();
    // BFV, TempMem, Payload + 2x PermMem = 5
    assert_eq!(sections.len(), 5);
    assert_eq!(sections[3]["Type"], "PermMem");
    assert_eq!(sections[3]["MemoryDataSize"], "0x2000000");
    assert_eq!(sections[4]["Type"], "PermMem");
    assert_eq!(sections[4]["MemoryDataSize"], "0x800000000");
}

#[test]
fn test_metadata_gen_with_additional_temp_mem() {
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().join("metadata_output.json");

    let layout = write_layout(
        output_dir.path(),
        r#"{
            "TempStack": "0x20000",
            "TempHeap": "0x20000",
            "Payload": "0x17000",
            "Metadata": "0x1000",
            "Ipl": "0x16000",
            "ResetVector": "0x8000",
            "ImageSize": "0x70000"
        }"#,
    );

    let mem_layout = write_memory_layout(
        output_dir.path(),
        r#"{
            "PermMem": [
                { "address": "0x0", "size": "0x2000000" }
            ],
            "TempMem": [
                { "address": "0x10000000", "size": "0x1000000" }
            ]
        }"#,
    );

    let status = Command::new(bin_path())
        .args([
            "--layout",
            layout.to_str().unwrap(),
            "--memory-layout",
            mem_layout.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(status.success());

    let content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let sections = parsed["Sections"].as_array().unwrap();
    // BFV, TempMem (from layout), TempMem (from memory-layout), Payload, PermMem = 5
    assert_eq!(sections.len(), 5);
    // First TempMem from image layout (TempStack + TempHeap)
    assert_eq!(sections[1]["Type"], "TempMem");
    // Second TempMem from memory layout
    assert_eq!(sections[2]["Type"], "TempMem");
    assert_eq!(sections[2]["MemoryAddress"], "0x10000000");
    assert_eq!(sections[2]["MemoryDataSize"], "0x1000000");
    // PermMem
    assert_eq!(sections[4]["Type"], "PermMem");
}

#[test]
fn test_metadata_gen_overlap_detection() {
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().join("metadata_output.json");

    let layout = write_layout(
        output_dir.path(),
        r#"{
            "TempStack": "0x20000",
            "TempHeap": "0x20000",
            "Payload": "0x17000",
            "Metadata": "0x1000",
            "Ipl": "0x16000",
            "ResetVector": "0x8000",
            "ImageSize": "0x70000"
        }"#,
    );

    // PermMem overlaps with itself (two regions at the same address)
    let mem_layout = write_memory_layout(
        output_dir.path(),
        r#"{
            "PermMem": [
                { "address": "0x0", "size": "0x2000000" },
                { "address": "0x1000000", "size": "0x2000000" }
            ],
            "TempMem": []
        }"#,
    );

    let status = Command::new(bin_path())
        .args([
            "--layout",
            layout.to_str().unwrap(),
            "--memory-layout",
            mem_layout.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(!status.success(), "should fail when memory regions overlap");
}

#[test]
fn test_metadata_gen_layout_without_tdparams() {
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().join("metadata_output.json");

    // Layout without TdParams or TdInfo
    let layout = write_layout(
        output_dir.path(),
        r#"{
            "TempStack": "0x20000",
            "TempHeap": "0x20000",
            "Payload": "0x17000",
            "Metadata": "0x1000",
            "Ipl": "0x16000",
            "ResetVector": "0x8000",
            "ImageSize": "0x70000"
        }"#,
    );

    let status = Command::new(bin_path())
        .args([
            "--layout",
            layout.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(status.success(), "should succeed without TdParams/TdInfo");

    let content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let sections = parsed["Sections"].as_array().unwrap();
    // Should have: BFV, TempMem, Payload (no TdParams, no TdInfo)
    assert_eq!(sections.len(), 3);
    assert_eq!(sections[0]["Type"], "BFV");
    assert_eq!(sections[1]["Type"], "TempMem");
    assert_eq!(sections[2]["Type"], "Payload");
}

#[test]
fn test_metadata_gen_sample_nrx_image_template() {
    // Verify the tool handles an NRX-style layout with a separate memory layout.
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().join("metadata_output.json");

    let layout = write_layout(
        output_dir.path(),
        r#"{
            "TdParams": "0x1000",
            "TempStack": "0x20000",
            "TempHeap": "0x20000",
            "TdInfo": "0x1000",
            "Metadata": "0x1000",
            "Payload": "0x10000",
            "Ipl": "0x10000",
            "ResetVector": "0x8000",
            "ImageSize": "0x6C000"
        }"#,
    );

    let mem_layout = write_memory_layout(
        output_dir.path(),
        r#"{
            "PermMem": [
                { "address": "0x0", "size": "0x2000000" }
            ]
        }"#,
    );

    let status = Command::new(bin_path())
        .args([
            "--layout",
            layout.to_str().unwrap(),
            "--memory-layout",
            mem_layout.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(status.success());

    let content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let sections = parsed["Sections"].as_array().unwrap();
    // TdParams, BFV, TempMem, Payload, TdInfo, PermMem
    assert_eq!(sections.len(), 6);
    assert_eq!(sections[5]["Type"], "PermMem");
}

#[test]
fn test_metadata_gen_missing_args() {
    let status = Command::new(bin_path())
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(!status.success(), "should fail with no arguments");
}

#[test]
fn test_metadata_gen_missing_layout_file() {
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().join("metadata_output.json");

    let status = Command::new(bin_path())
        .args([
            "--layout",
            "/nonexistent/path/layout.json",
            "--out",
            output_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(
        !status.success(),
        "should fail when layout file does not exist"
    );
}

#[test]
fn test_metadata_gen_duplicate_args() {
    let output_dir = tempfile::tempdir().unwrap();
    let output_path = output_dir.path().join("metadata_output.json");

    let layout = write_layout(output_dir.path(), r#"{"ImageSize": "0x10000"}"#);

    let status = Command::new(bin_path())
        .args([
            "--layout",
            layout.to_str().unwrap(),
            "--layout",
            layout.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run td-shim-metadata-gen");

    assert!(!status.success(), "should fail with duplicate --layout");
}

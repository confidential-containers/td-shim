// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Integration tests for td-shim-image-layout-gen binary.
//!
//! Note: Full end-to-end tests require actual build artifacts (ELF binaries,
//! reset vector). These tests validate argument parsing and error handling.
//! For full integration testing with real artifacts, use the project's CI
//! build pipeline which produces the required binaries first.

use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
    let mut path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push("td-shim-image-layout-gen");
    path
}

#[test]
fn test_image_layout_missing_args() {
    let status = Command::new(bin_path())
        .status()
        .expect("failed to run td-shim-image-layout-gen");

    assert!(!status.success(), "should fail with no arguments");
}

#[test]
fn test_image_layout_missing_payload_binary() {
    let status = Command::new(bin_path())
        .args(["--project-root", "/tmp"])
        .status()
        .expect("failed to run td-shim-image-layout-gen");

    assert!(!status.success(), "should fail without --payload-binary");
}

#[test]
fn test_image_layout_missing_project_root() {
    let status = Command::new(bin_path())
        .args(["--payload-binary", "some-payload"])
        .status()
        .expect("failed to run td-shim-image-layout-gen");

    assert!(!status.success(), "should fail without --project-root");
}

#[test]
fn test_image_layout_unknown_argument() {
    let output = Command::new(bin_path())
        .args(["--unknown-flag", "value"])
        .output()
        .expect("failed to run td-shim-image-layout-gen");

    assert!(
        !output.status.success(),
        "should fail with unknown argument"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown argument"),
        "should report unknown argument"
    );
}

#[test]
fn test_image_layout_duplicate_project_root() {
    let output = Command::new(bin_path())
        .args([
            "--project-root",
            "/tmp",
            "--project-root",
            "/tmp",
            "--payload-binary",
            "test",
        ])
        .output()
        .expect("failed to run td-shim-image-layout-gen");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("specified more than once"));
}

#[test]
fn test_image_layout_nonexistent_artifacts() {
    // Even with valid args, should fail if the target directory/artifacts don't exist
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(bin_path())
        .args([
            "--project-root",
            tmp.path().to_str().unwrap(),
            "--payload-binary",
            "nonexistent-payload",
        ])
        .output()
        .expect("failed to run td-shim-image-layout-gen");

    assert!(
        !output.status.success(),
        "should fail when artifact files don't exist"
    );
}

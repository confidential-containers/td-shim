// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::{
    env, format,
    path::{Path, PathBuf},
    process::Command,
};

use td_layout::build_time;

// TODO: move it into td-layout
pub const INITIALLY_ACCEPTED_MEMORY_SIZE: u32 = 0x80_0000;

fn nasm(file: &Path, arch: &str, out_file: &Path, args: &[&str]) -> Command {
    let oformat = match arch {
        "x86_64" => ("win64"),
        "x86" => ("win32"),
        "bin" => ("bin"),
        _ => panic!("unsupported arch: {}", arch),
    };
    let mut c = Command::new("nasm");
    let _ = c
        .arg("-o")
        .arg(out_file.to_str().expect("Invalid path"))
        .arg("-f")
        .arg(oformat)
        .arg(file);
    for arg in args {
        let _ = c.arg(*arg);
    }
    c
}

fn run_command(mut cmd: Command) {
    eprintln!("running {:?}", cmd);
    let status = cmd.status().unwrap_or_else(|e| {
        panic!("failed to execute [{:?}]: {}", cmd, e);
    });
    if !status.success() {
        panic!("execution failed");
    }
}

fn main() {
    // tell cargo when to re-run the script
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rerun-if-changed={}",
        Path::new("ResetVector/ResetVector.asm").to_str().unwrap()
    );

    let reset_vector_src_dir = get_cargo_manifest_dir().join("ResetVector");
    let reset_vector_bin_file = get_target_output_dir().join("ResetVector.bin");

    let use_tdx_emulation_arg = format!(
        "-DUSE_TDX_EMULATION={}",
        if tdx_tdcall::USE_TDX_EMULATION {
            1u8
        } else {
            0u8
        }
    );
    let td_shim_ipl_base_arg = format!("-DTOP_OF_BFV=0x{:X}", build_time::TD_SHIM_IPL_BASE);
    let td_mailbox_base_arg = format!("-DTD_MAILBOX_BASE=0x{:X}", build_time::TD_SHIM_MAILBOX_BASE);
    let td_mailbox_size_arg = format!("-DTD_MAILBOX_SIZE=0x{:X}", build_time::TD_SHIM_MAILBOX_SIZE);
    let td_shim_hob_base_arg = format!("-DTD_HOB_BASE=0x{:X}", build_time::TD_SHIM_HOB_BASE);
    let td_shim_hob_size_arg = format!("-DTD_HOB_SIZE=0x{:X}", build_time::TD_SHIM_HOB_SIZE);
    let td_shim_tmp_stack_base_arg = format!(
        "-DTEMP_STACK_BASE=0x{:X}",
        build_time::TD_SHIM_TEMP_STACK_BASE
    );
    let td_shim_tmp_stack_size_arg = format!(
        "-DTEMP_STACK_SIZE=0x{:X}",
        build_time::TD_SHIM_TEMP_STACK_SIZE
    );
    let td_shim_tmp_heap_base_arg =
        format!("-DTEMP_RAM_BASE=0x{:X}", build_time::TD_SHIM_TEMP_HEAP_BASE);
    let td_shim_tmp_heap_size_arg =
        format!("-DTEMP_RAM_SIZE=0x{:X}", build_time::TD_SHIM_TEMP_HEAP_SIZE);

    let loaded_sec_entrypoint_base = format!(
        "-DTD_SHIM_RESET_SEC_CORE_ENTRY_POINT_ADDR=0x{:X}",
        build_time::TD_SHIM_RESET_SEC_CORE_ENTRY_POINT_ADDR
    );
    let loaded_sec_core_base = format!(
        "-DTD_SHIM_RESET_SEC_CORE_BASE_ADDR=0x{:X}",
        build_time::TD_SHIM_RESET_SEC_CORE_BASE_ADDR
    );
    let loaded_sec_core_size = format!(
        "-DTD_SHIM_RESET_SEC_CORE_SIZE_ADDR=0x{:X}",
        build_time::TD_SHIM_RESET_SEC_CORE_SIZE_ADDR
    );
    let accepted_memory_size = format!(
        "-DINITIALLY_ACCEPTED_MEMORY_SIZE=0x{:X}",
        crate::INITIALLY_ACCEPTED_MEMORY_SIZE
    );

    let _ = env::set_current_dir(reset_vector_src_dir.as_path());
    run_command(nasm(
        Path::new("ResetVector.nasm"),
        "bin",
        reset_vector_bin_file.as_path(),
        &[
            &use_tdx_emulation_arg,
            &td_shim_ipl_base_arg,
            &td_mailbox_base_arg,
            &td_mailbox_size_arg,
            &td_shim_hob_base_arg,
            &td_shim_hob_size_arg,
            &td_shim_tmp_stack_base_arg,
            &td_shim_tmp_stack_size_arg,
            &td_shim_tmp_heap_base_arg,
            &td_shim_tmp_heap_size_arg,
            &loaded_sec_entrypoint_base,
            &loaded_sec_core_base,
            &loaded_sec_core_size,
            &accepted_memory_size,
        ],
    ));
}

fn get_target_output_dir() -> PathBuf {
    // In build script, this is set to the folder
    // where the build script should place its output.
    let out_dir = env::var("OUT_DIR").unwrap();
    let path = PathBuf::from(out_dir);

    // Build script outputs relative to target outputs.
    // Therefore we get target outputs path.
    path.join("../../..")
}

fn get_cargo_manifest_dir() -> PathBuf {
    // Environment variables Cargo sets for crates
    // The directory containing the manifest of your package.
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
}

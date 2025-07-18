// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use std::{
    env, format,
    mem::size_of,
    path::{Path, PathBuf},
    process::{exit, Command},
};
use td_layout::build_time;

fn nasm(file: &Path, arch: &str, out_file: &Path, args: &[&str]) -> Command {
    let oformat = match arch {
        "x86_64" => "win64",
        "x86" => "win32",
        "bin" => "bin",
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

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
// clang is only required when building ring with the x86_64-unknown-none target. #109
fn check_environment() -> Result<()> {
    use anyhow::anyhow;
    use which::which;
    const CC_ENV_VAR: &str = "CC_x86_64_unknown_uefi";
    const AS_ENV_VAR: &str = "AS";
    const AR_ENV_VAR: &str = "AR_x86_64_unknown_uefi";

    // Defaults to 'cc' but also honours the CC_ENV_VAR environment variable.
    let cfg = cc::Build::new().try_get_compiler()?;

    // GCC cannot be used as it fails to link.
    let required_compiler = "clang";

    let required_assembler = "nasm";
    let required_archiver = "llvm-ar";

    let cc_path = cfg.path().to_path_buf();
    let as_path =
        PathBuf::from(env::var(AS_ENV_VAR).unwrap_or_else(|_| required_assembler.to_string()));
    let ar_path =
        PathBuf::from(env::var(AR_ENV_VAR).unwrap_or_else(|_| required_archiver.to_string()));

    struct BuildDependency<'a> {
        path: PathBuf,
        description: &'a str,
        env_var: &'a str,
        required_cmd: &'a str,
    }

    // List is not sorted alphabetically to help the user on error: the
    // compiler name is more commonly known than the archiver name, so if
    // that's missing, show it first.
    //
    // Also installing the missing compiler will probably install the archiver
    // as a dependency.
    let cmds = &[
        BuildDependency {
            path: as_path,
            description: "assembler",
            env_var: AS_ENV_VAR,
            required_cmd: required_assembler,
        },
        BuildDependency {
            path: cc_path,
            description: "compiler",
            env_var: CC_ENV_VAR,
            required_cmd: required_compiler,
        },
        BuildDependency {
            path: ar_path,
            description: "archiver",
            env_var: AR_ENV_VAR,
            required_cmd: required_archiver,
        },
    ];

    for cmd in cmds {
        let BuildDependency {
            path,
            description,
            env_var,
            required_cmd,
        } = cmd;

        println!("cargo:rerun-if-env-changed={}", env_var);

        let resolved_path = which(path)
            .map_err(|e| {
                anyhow!(
                    "cannot find {:} command {:?}: {:?} (expected {:?})",
                    description,
                    path,
                    e,
                    required_cmd
                )
            })?
            .canonicalize()
            .map_err(|e| {
                anyhow!(
                    "cannot resolve {:} command {:?}: {:?}",
                    description,
                    path,
                    e
                )
            })?;

        if !resolved_path
            .to_str()
            .ok_or("cannot convert path to string")
            .map_err(|e| anyhow!("{:?}", e))?
            .contains(required_cmd)
        {
            return Err(anyhow!(
                "{:} command {:?} is not {:?} - do you need to set ${:}?",
                description,
                path,
                required_cmd,
                env_var
            ));
        }
    }

    Ok(())
}

fn real_main() -> Result<()> {
    // tell cargo when to re-run the script
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    check_environment()?;

    println!(
        "cargo:rerun-if-changed={}",
        Path::new("ResetVector/ResetVector.nasm").to_str().unwrap()
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

    #[cfg(feature = "no-mailbox")]
    let mailbox_support = format!("-DMAILBOX_SUPPORT={}", 0u8);
    #[cfg(not(feature = "no-mailbox"))]
    let mailbox_support = format!("-DMAILBOX_SUPPORT={}", 1u8);
    let td_mailbox_base_arg = format!("-DTD_MAILBOX_BASE=0x{:X}", build_time::TD_SHIM_MAILBOX_BASE);
    let td_mailbox_size_arg = format!("-DTD_MAILBOX_SIZE=0x{:X}", build_time::TD_SHIM_MAILBOX_SIZE);

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
        build_time::TD_SHIM_SEC_CORE_INFO_BASE,
    );
    let loaded_sec_core_base = format!(
        "-DTD_SHIM_RESET_SEC_CORE_BASE_ADDR=0x{:X}",
        build_time::TD_SHIM_SEC_CORE_INFO_BASE + size_of::<u32>() as u32,
    );
    let loaded_sec_core_size = format!(
        "-DTD_SHIM_RESET_SEC_CORE_SIZE_ADDR=0x{:X}",
        build_time::TD_SHIM_SEC_CORE_INFO_BASE + 2 * size_of::<u32>() as u32
    );
    let tdaccept = format!(
        "-DTDACCEPT_SUPPORT={}",
        if tdx_tdcall::TDACCEPT_SUPPORT {
            1u8
        } else {
            0u8
        }
    );
    let fw_top = format!(
        "-DFW_TOP=0x{:X}",
        build_time::TD_SHIM_FIRMWARE_BASE as u64 + build_time::TD_SHIM_FIRMWARE_SIZE as u64,
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
            &td_shim_tmp_stack_base_arg,
            &td_shim_tmp_stack_size_arg,
            &td_shim_tmp_heap_base_arg,
            &td_shim_tmp_heap_size_arg,
            &loaded_sec_entrypoint_base,
            &loaded_sec_core_base,
            &loaded_sec_core_size,
            &tdaccept,
            &mailbox_support,
            &fw_top,
        ],
    ));

    Ok(())
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

fn main() {
    if let Err(e) = real_main() {
        eprintln!("ERROR: {:#}", e);
        exit(1);
    }
}

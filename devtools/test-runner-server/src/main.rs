// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::{arg, command, ArgAction};
use serde_json;
use std::{
    env, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    time::Duration,
};

const RUN_ARGS: &[&str] = &["--no-reboot", "-s"];
const TEST_ARGS: &[&str] = &[
    "-device",
    "isa-debug-exit,iobase=0xf4,iosize=0x04",
    "-serial",
    "stdio",
    "-display",
    "none",
    "--no-reboot",
];
const TEST_TIMEOUT_SECS: u64 = 10;

fn main() {
    let matches = command!()
        .arg(
            arg!([kernel] "Path of kernel file be executed by the virtual machine")
                .required(true)
                .action(ArgAction::Set),
        )
        .arg(
            arg!(
              --"no-run" "Dry-run mode, do not actually spawn the virtual machine"
            )
            .required(false)
            .action(ArgAction::SetTrue),
        )
        .get_matches();

    // Safe to unwrap because they are mandatory arguments.
    let kernel = matches.get_one::<String>("kernel").unwrap();
    let kernel_binary_path = {
        let path = PathBuf::from(kernel);
        path.canonicalize().expect(&format!(
            "Invalid kernel file path {}: {}",
            kernel,
            io::Error::last_os_error()
        ))
    };

    let bios = kernel_binary_path.parent().unwrap().join(format!(
        "boot-bios-{}.img",
        kernel_binary_path.file_name().unwrap().to_str().unwrap()
    ));
    bootloader::BiosBoot::new(&kernel_binary_path)
        .create_disk_image(&bios)
        .unwrap();

    //let output = matches.value_of("no-run")
    if matches.get_flag("no-run") {
        println!("Created disk image at `{}`", bios.display());
        return;
    }

    let mut run_cmd = Command::new("qemu-system-x86_64");
    run_cmd
        .arg("-drive")
        .arg(format!("format=raw,file={}", bios.display()));

    let binary_kind = runner_utils::binary_kind(&kernel_binary_path);
    if binary_kind.is_test() {
        run_cmd.args(TEST_ARGS);

        let exit_status = run_test_command(run_cmd);
        match exit_status.code() {
            // TODO: should this be QemuExitCode::Success?
            Some(33) => {} // success
            other => panic!("Test failed (exit code: {:?})", other),
        }
    } else {
        run_cmd.args(RUN_ARGS);

        let exit_status = run_cmd.status().unwrap();
        if !exit_status.success() {
            std::process::exit(exit_status.code().unwrap_or(1));
        }
    }
}

fn run_test_command(mut cmd: Command) -> ExitStatus {
    runner_utils::run_with_timeout(&mut cmd, Duration::from_secs(TEST_TIMEOUT_SECS)).unwrap()
}

fn locate_manifest() -> Result<PathBuf, LocateError> {
    let cargo = env::var("CARGO").unwrap_or("cargo".to_owned());
    let output = Command::new(cargo).arg("locate-project").output().unwrap();
    if !output.status.success() {
        return Err(LocateError::CargoExecution {
            stderr: output.stderr,
        });
    }

    let output = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&output).expect("JSON was not well-formatted");
    let root = parsed["root"].as_str().ok_or(LocateError::NoRoot)?;
    Ok(PathBuf::from(root))
}

fn locate_bootloader(dependency_name: &str) -> Result<PathBuf, LocateError> {
    let metadata = metadata().unwrap();

    let root = metadata["resolve"]["root"]
        .as_str()
        .ok_or(LocateError::MetadataInvalid)?;

    let root_resolve = metadata["resolve"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == root)
        .ok_or(LocateError::MetadataInvalid)?;

    let dependency = root_resolve["deps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == dependency_name)
        .ok_or(LocateError::DependencyNotFound)?;
    let dependency_id = dependency["pkg"]
        .as_str()
        .ok_or(LocateError::MetadataInvalid)?;

    let dependency_package = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == dependency_id)
        .ok_or(LocateError::MetadataInvalid)?;
    let dependency_manifest = dependency_package["manifest_path"]
        .as_str()
        .ok_or(LocateError::MetadataInvalid)?;

    Ok(dependency_manifest.into())
}

fn metadata() -> Result<serde_json::Value, LocateError> {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.arg("metadata");
    cmd.arg("--format-version").arg("1");
    let output = cmd.output().unwrap();

    if !output.status.success() {
        return Err(LocateError::CargoExecution {
            stderr: output.stderr,
        });
    }

    let output = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&output).expect("JSON was not well-formatted");

    Ok(parsed)
}

// Errors that can occur while retrieving the cargo manifest path.
#[derive(Debug)]
enum LocateError {
    // The command `cargo locate-project` did not exit successfully.
    CargoExecution {
        // The standard error output of `cargo locate-project`.
        stderr: Vec<u8>,
    },
    // The JSON output of `cargo locate-project` did not contain the expected "root" string.
    NoRoot,
    // The project metadata returned from `cargo metadata` was not valid.
    MetadataInvalid,
    // No dependency with the given name found in the project metadata.
    DependencyNotFound,
}

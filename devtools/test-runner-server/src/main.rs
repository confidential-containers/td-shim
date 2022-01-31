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

use clap::{app_from_crate, arg};
use std::{
    io,
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
    let matches = app_from_crate!()
        .arg(
            arg!([kernel] "Path of kernel file be executed by the virtual machine")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(
              --"no-run" "Dry-run mode, do not actually spawn the virtual machine"
            )
            .required(false)
            .allow_invalid_utf8(false),
        )
        .get_matches();

    // Safe to unwrap because they are mandatory arguments.
    let kernel = matches.value_of("kernel").unwrap();
    let kernel_binary_path = {
        let path = PathBuf::from(kernel);
        path.canonicalize().expect(&format!(
            "Invalid kernel file path {}: {}",
            kernel,
            io::Error::last_os_error()
        ))
    };
    let bios = create_disk_images(&kernel_binary_path);

    //let output = matches.value_of("no-run")
    if matches.is_present("no-run") {
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

fn create_disk_images(kernel_binary_path: &Path) -> PathBuf {
    let bootloader_manifest_path = bootloader_locator::locate_bootloader("bootloader").unwrap();
    let kernel_manifest_path = locate_cargo_manifest::locate_manifest().unwrap();

    let mut build_cmd = Command::new(env!("CARGO"));
    build_cmd.current_dir(bootloader_manifest_path.parent().unwrap());
    build_cmd.arg("builder");
    build_cmd
        .arg("--kernel-manifest")
        .arg(&kernel_manifest_path);
    build_cmd.arg("--kernel-binary").arg(&kernel_binary_path);
    build_cmd
        .arg("--target-dir")
        .arg(kernel_manifest_path.parent().unwrap().join("target"));
    build_cmd
        .arg("--out-dir")
        .arg(kernel_binary_path.parent().unwrap());
    build_cmd.arg("--quiet");

    if !build_cmd.status().unwrap().success() {
        panic!("build failed");
    }

    let kernel_binary_name = kernel_binary_path.file_name().unwrap().to_str().unwrap();
    let disk_image = kernel_binary_path
        .parent()
        .unwrap()
        .join(format!("boot-bios-{}.img", kernel_binary_name));
    if !disk_image.exists() {
        panic!(
            "Disk image does not exist at {} after bootloader build",
            disk_image.display()
        );
    }
    disk_image
}

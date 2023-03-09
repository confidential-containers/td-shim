// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Ok, Result};
use clap::{Parser, ValueEnum};
use lazy_static::lazy_static;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use xshell::{cmd, Shell};

const TD_SHIM_DEFAULT_FEATURES: &str = "main,tdx";

lazy_static! {
    static ref PROJECT_ROOT: &'static Path =
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    static ref SHIM_OUTPUT: PathBuf = PROJECT_ROOT.join("target/x86_64-unknown-none/");
    static ref IMAGE_OUTPUT: PathBuf = PROJECT_ROOT.join("target/release/final.bin");
    static ref METADATA: PathBuf = PROJECT_ROOT.join("td-shim-tools/etc/metadata.json");
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum PayloadType {
    /// Payload Binary is bzImage or vmlinux, follow Linux boot protocol
    Linux,
    /// Payload Binary is a PE/COFF or ELF executable image as payload
    Executable,
}

#[derive(Clone, Parser)]
pub(crate) struct BuildArgs {
    /// Build artifacts in release mode, with optimizations and without log messages
    #[arg(long)]
    release: bool,
    /// Type of payload to be launched by td-shim
    #[arg(short = 't', long)]
    payload_type: Option<PayloadType>,
    /// Path of the output td-shim image file
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Disable the `default` features of td-shim crate, this flag will be set
    /// automatically when the payload type is executable
    #[arg(long)]
    no_default_features: bool,
    /// List of features to activate separated by comma
    #[arg(long)]
    features: Option<String>,
    /// Path of customized metadata configuration file
    #[arg(short, long)]
    metadata: Option<PathBuf>,
    /// Path of customized layout configuration file, the layout source file of the payload
    /// type specified by `payload-type` will be overwritten
    #[arg(short, long)]
    layout: Option<PathBuf>,
    /// Package the payload binary into td-shim image
    #[arg(short, long)]
    payload: Option<PathBuf>,
    /// Package the example payload binary into td-shim image, payload-type will be set to
    /// executable.
    #[arg(long)]
    example_payload: bool,
    /// <Guid>,<FilePath> Enroll raw files into into CFV of td-shim image
    #[arg(long)]
    enroll_file: Option<Vec<String>>,
    /// <Guid>,<FilePath> Enroll public key file into CFV of td-shim image
    #[arg(long, requires = "enroll_key_hash_alg")]
    enroll_key: Option<String>,
    /// Hash algorithm used by the enrolling public key file
    #[arg(long, short = 'H', requires = "enroll_key")]
    enroll_key_hash_alg: Option<String>,
}

impl BuildArgs {
    pub fn build(&self) -> Result<PathBuf> {
        if let Some(payload_type) = self.payload_type {
            if payload_type == PayloadType::Linux && self.example_payload {
                return Err(anyhow!("Invalid payload type for example payload"));
            }
        }

        let (reset_vector, shim) = self.build_shim()?;

        let payload = if let Some(payload) = &self.payload {
            Some(fs::canonicalize(payload)?)
        } else if self.example_payload {
            Some(self.build_example_payload()?)
        } else {
            None
        };

        let bin = self.build_image(reset_vector, shim, payload)?;
        self.enroll(bin.as_path())?;

        Ok(bin)
    }

    fn build_shim_layout(&self) -> Result<()> {
        let layout_config = if let Some(layout) = &self.layout {
            fs::canonicalize(layout)?
        } else {
            return Ok(());
        };

        let sh = Shell::new()?;
        sh.change_dir(PROJECT_ROOT.join("devtools/td-layout-config"));
        cmd!(sh, "cargo run -- ")
            .args(["--config", layout_config.to_str().unwrap()])
            .arg(PROJECT_ROOT.join("td-layout/src"))
            .run()?;
        Ok(())
    }

    fn build_shim(&self) -> Result<(PathBuf, PathBuf)> {
        self.build_shim_layout()?;

        let sh = Shell::new()?;
        cmd!(sh, "cargo xbuild -p td-shim --target x86_64-unknown-none")
            .args(["--features", self.features().as_str()])
            .args(["--profile", self.profile()])
            .run()?;

        Self::strip("td-shim")?;

        Ok((
            SHIM_OUTPUT
                .join(&self.profile_path())
                .join("ResetVector.bin"),
            SHIM_OUTPUT.join(&self.profile_path()).join("td-shim"),
        ))
    }

    fn build_example_payload(&self) -> Result<PathBuf> {
        let sh = Shell::new()?;
        cmd!(
            sh,
            "cargo xbuild -p td-payload --bin example --target x86_64-unknown-none"
        )
        .args(["--features", "tdx,start,cet-shstk,stack-guard"])
        .args(["--profile", self.profile()])
        .run()?;

        Self::strip("example")?;

        Ok(SHIM_OUTPUT.join(&self.profile_path()).join("example"))
    }

    fn build_image(
        &self,
        reset_vector: PathBuf,
        shim: PathBuf,
        payload: Option<PathBuf>,
    ) -> Result<PathBuf> {
        let sh = Shell::new()?;
        let mut cmd = cmd!(
            sh,
            "cargo run -p td-shim-tools --bin td-shim-ld --features linker --"
        );

        if self.payload_type() == PayloadType::Executable {
            cmd = cmd.args(["-t", "executable"]);
        }

        cmd = cmd
            .args(&[reset_vector])
            .args(&[shim])
            .args(&["-o", self.output()?.to_str().unwrap()]);

        if let Some(metadata) = &self.metadata {
            cmd = cmd.args(&["-m", fs::canonicalize(metadata)?.to_str().unwrap()]);
        }

        if let Some(payload) = payload {
            cmd.args(&["-p", payload.to_str().unwrap()])
        } else {
            cmd
        }
        .run()?;

        Ok(self.output()?.to_path_buf())
    }

    fn enroll(&self, image: &Path) -> Result<()> {
        if self.enroll_file.is_none() && self.enroll_key.is_none() {
            return Ok(());
        }

        let sh = Shell::new()?;
        let mut cmd = cmd!(sh, "cargo run -p td-shim-tools --bin td-shim-enroll")
            .args(&[image])
            .args(&["-o", self.output()?.to_str().unwrap()]);

        if let Some(files) = self.enroll_file.as_ref() {
            for f in files {
                let f = f.split(",").map(|s| s.to_string()).collect::<Vec<String>>();
                cmd = cmd.args(&["-f", f[0].as_str()]).arg(f[1].as_str());
            }
        }

        if let Some(key) = self.enroll_key.as_ref() {
            let key = key
                .split(",")
                .map(|s| s.to_string())
                .collect::<Vec<String>>();
            cmd.args(&["-k", key[0].as_str()])
                .arg(key[1].as_str())
                .args(&["-H", self.enroll_key_hash_alg()?.as_str()])
        } else {
            cmd
        }
        .run()?;

        Ok(())
    }

    fn payload_type(&self) -> PayloadType {
        self.payload_type.unwrap_or_else(|| {
            if self.example_payload {
                PayloadType::Executable
            } else {
                PayloadType::Linux
            }
        })
    }

    fn profile(&self) -> &str {
        if self.release {
            "release"
        } else {
            "dev"
        }
    }

    fn profile_path(&self) -> &str {
        if self.release {
            "release"
        } else {
            "debug"
        }
    }

    fn features(&self) -> String {
        let mut features =
            if self.no_default_features || self.payload_type() == PayloadType::Executable {
                Vec::new()
            } else {
                TD_SHIM_DEFAULT_FEATURES
                    .split(",")
                    .map(|s| s.to_string())
                    .collect()
            };

        if let Some(selected) = &self.features {
            for s in selected.split(",") {
                features.push(s.to_string());
            }
        }

        features.join(",")
    }

    fn output(&self) -> Result<PathBuf> {
        let path = self.output.as_ref().unwrap_or(&IMAGE_OUTPUT);

        // Get the absolute path of the target file
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()?.join(path)
        };
        Ok(absolute)
    }

    fn enroll_key_hash_alg(&self) -> Result<String> {
        self.enroll_key_hash_alg
            .clone()
            .ok_or(anyhow!("Hash algorithm of public key is not specified.."))
    }

    fn strip(name: &str) -> Result<()> {
        let sh = Shell::new()?;
        cmd!(
            sh,
            "cargo run -p td-shim-tools --bin td-shim-strip-info -- --target x86_64-unknown-none"
        )
        .args(["-n", name])
        .run()?;

        Ok(())
    }
}

// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! A simple tool to calculate td-payload and parameter's reference value due to given kernel

use anyhow::*;
use clap::{arg, command};
use parse_int::parse;
use sha2::Digest;
use std::{convert::TryFrom, path::Path};

pub const KERNEL_SIZE: &str = "0x2000000";
pub const KERNEL_PARAM_SIZE: &str = "0x1000";

fn kernel(path: &str, size: &str) -> Result<String> {
    let path = Path::new(path).to_path_buf();
    let siz = parse::<u64>(size)?;
    let file_size = std::fs::metadata(&path)?.len();
    if file_size > siz {
        bail!("File size should be less than `kernel-size`");
    }
    let buf = std::fs::read(path)?;
    padding_digest(buf, siz as usize)
}

fn param(param: &str, size: &str) -> Result<String> {
    let param = Vec::try_from(param)?;
    let siz = parse::<usize>(size)?;
    padding_digest(param, siz)
}

fn padding_digest(mut buf: Vec<u8>, len: usize) -> Result<String> {
    let diff = len - buf.len();

    buf.extend_from_slice(&vec![0; diff as usize]);
    let mut hasher = sha2::Sha384::new();
    hasher.update(&buf);
    let res = hasher.finalize();
    Ok(hex::encode(res))
}

fn main() {
    let matches = command!()
        .subcommand_required(true)
        .subcommand(
            command!("kernel")
                .arg(
                    arg!(-k --kernel "path to vmlinuz kernel")
                        .required(true)
                        .takes_value(true)
                        .allow_invalid_utf8(false),
                )
                .arg(
                    arg!(-s --"size" "KERNEL_SIZE of the target td-shim")
                        .required(false)
                        .default_value(KERNEL_SIZE),
                ),
        )
        .subcommand(
            command!("param")
                .arg(
                    arg!(-p --parameter "kernel parameter string")
                        .required(true)
                        .takes_value(true)
                        .allow_invalid_utf8(false),
                )
                .arg(
                    arg!(-s --"size" "KERNEL_PARAM_SIZE of the target td-shim")
                        .required(false)
                        .default_value(KERNEL_PARAM_SIZE),
                ),
        )
        .get_matches();

    let res = match matches.subcommand() {
        Some(("kernel", args)) => {
            let path = args.value_of("kernel").unwrap();
            let siz = args.value_of("size").unwrap();
            kernel(path, siz)
        }
        Some(("param", args)) => {
            let parameter = args.value_of("parameter").unwrap();
            let siz = args.value_of("size").unwrap();
            param(parameter, siz)
        }
        Some((_, _)) => unreachable!(),
        None => unreachable!(),
    };

    match res {
        std::result::Result::Ok(res) => println!("{res}"),
        Err(e) => eprintln!("[ERROR]: {}", e.to_string()),
    }
}

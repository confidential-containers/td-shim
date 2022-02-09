// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[macro_use]
extern crate clap;

use std::str::FromStr;
use std::{env, io, path::Path};

use log::{error, LevelFilter};
use ring::digest;

const TDSHIM_SB_NAME: &str = "final.sb.bin";

fn main() -> io::Result<()> {
    use env_logger::Env;
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");
    env_logger::init_from_env(env);

    let matches = app_from_crate!()
        .about("Enroll hash value of a public key into shim binary for secure boot")
        .arg(
            arg!([tdshim] "shim binary file")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!([key] "public key file for enrollment")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-H --hash "hash algorithm to calculate public key digest")
                .required(false)
                .takes_value(true)
                .default_value("SHA384"),
        )
        .arg(
            arg!(-l --"log-level" "logging level: [off, error, warn, info, debug, trace]")
                .required(false)
                .default_value("info"),
        )
        .arg(
            arg!(-o --output "name of the output shim binary file with enrolled public key")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .get_matches();

    if let Ok(lvl) = LevelFilter::from_str(matches.value_of("log-level").unwrap()) {
        log::set_max_level(lvl);
    }

    // Safe to unwrap() because they are mandatory or have default values.
    let tdshim_file = matches.value_of("tdshim").unwrap();
    let key_file = matches.value_of("key").unwrap();
    let hash_alg = matches.value_of("hash").unwrap();
    let output_file = match matches.value_of("output") {
        Some(v) => Path::new(v).to_path_buf(),
        None => {
            let p = Path::new(tdshim_file).canonicalize().map_err(|e| {
                error!("Invalid output file path {}: {}", tdshim_file, e);
                e
            })?;
            p.parent().unwrap_or(Path::new("/")).join(TDSHIM_SB_NAME)
        }
    };

    // Hash public key
    let hash_alg = match hash_alg {
        "SHA384" => &digest::SHA384,
        _ => {
            error!("Unsupported hash algorithm {}", hash_alg);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported hash algorithm",
            ));
        }
    };

    td_shim_tools::enroller::enroll_key(tdshim_file, key_file, output_file, hash_alg)
}

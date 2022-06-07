// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[macro_use]
extern crate clap;
use core::mem::size_of;
use log::{error, LevelFilter};
use serde_json;
use sha2::{Digest, Sha384};
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;
use std::{env, io, path::Path};
use std::{fs, io::Write};
use td_shim_tools::tee_info_hash::{Manifest, TdInfoStruct, SHA384_DIGEST_SIZE};

const TEE_INFO_HASH_BIN: &str = "tee_info_hash.bin";
const TDINFO_SIZE: usize = size_of::<TdInfoStruct>();

struct Config {
    // A json format td manifest
    pub manifest: String,
    // TD shim image file path
    pub image: String,
    // Output binary of tee info hash
    pub output: PathBuf,
    // Log level
    pub log_level: String,
}

#[derive(Debug)]
pub enum ConfigParseError {
    InvalidInputFilePath,
    InvalidLogLevel,
}

impl Config {
    pub fn new() -> Result<Self, ConfigParseError> {
        let matches = command!()
            .arg(
                arg!(-i --image "shim binary file")
                    .required(true)
                    .takes_value(true)
                    .allow_invalid_utf8(false),
            )
            .arg(
                arg!(-m --manifest "td manifest")
                    .required(true)
                    .takes_value(true)
                    .allow_invalid_utf8(false),
            )
            .arg(
                arg!(-o --"out_bin" "output tee info hash binary")
                    .required(false)
                    .takes_value(true)
                    .allow_invalid_utf8(false),
            )
            .arg(
                arg!(-l --"log-level" "logging level: [off, error, warn, info, debug, trace]")
                    .required(false)
                    .default_value("info"),
            )
            .get_matches();

        // Safe to unwrap() because they are mandatory or have default values.
        let image = matches.value_of("image").unwrap().to_string();
        let output = match matches.value_of("out_bin") {
            Some(v) => Path::new(v).to_path_buf(),
            None => {
                let p = Path::new(&image)
                    .canonicalize()
                    .map_err(|_| ConfigParseError::InvalidInputFilePath)?;
                p.parent().unwrap_or(Path::new("/")).join(TEE_INFO_HASH_BIN)
            }
        };
        let manifest = matches.value_of("manifest").unwrap().to_string();
        let log_level = String::from_str(matches.value_of("log-level").unwrap())
            .map_err(|_| ConfigParseError::InvalidLogLevel)?;

        Ok(Self {
            manifest,
            image,
            output,
            log_level,
        })
    }
}

fn main() -> io::Result<()> {
    use env_logger::Env;
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");
    env_logger::init_from_env(env);
    let config = Config::new().map_err(|e| {
        error!("Parse command line error: {:?}", e);
        io::Error::new(io::ErrorKind::Other, "Invalid command line parameter")
    })?;

    if let Ok(lvl) = LevelFilter::from_str(config.log_level.as_str()) {
        log::set_max_level(lvl);
    }

    let mut image = File::open(&config.image).expect("Failed to open firmware\n");
    let image_size = fs::metadata(config.image).unwrap().len();

    let configuration_manifest_json =
        fs::read_to_string(config.manifest).expect("Failed to open configuration manifest file!\n");
    let configuration: Manifest = serde_json::from_str(&configuration_manifest_json)?;

    assert!(configuration.attributes.len() <= size_of::<u64>());
    assert!(configuration.xfam.len() <= size_of::<u64>());
    assert_eq!(configuration.mrconfigid.len(), SHA384_DIGEST_SIZE);
    assert_eq!(configuration.mrowner.len(), SHA384_DIGEST_SIZE);
    assert_eq!(configuration.mrownerconfig.len(), SHA384_DIGEST_SIZE);

    let mut tee_info = TdInfoStruct {
        attributes: configuration.attributes,
        xfam: configuration.xfam,
        mrconfig_id: configuration.mrconfigid,
        mrowner: configuration.mrowner,
        mrownerconfig: configuration.mrownerconfig,
        ..Default::default()
    };

    tee_info.build_mrtd(&mut image, image_size);
    log::info!("{}", &tee_info);

    log::info!(
        "* Generate tee hash info binary file {}",
        &config.output.display()
    );
    let mut sha384hasher = Sha384::new();
    let mut buffer: [u8; TDINFO_SIZE] = [0; TDINFO_SIZE];
    tee_info.pack(&mut buffer);
    sha384hasher.update(buffer);
    let hash = sha384hasher.finalize();

    let mut tee_info_hash_file =
        File::create(&config.output).expect("Failed to create tee info hash file!\n");
    tee_info_hash_file
        .write_all(&hash)
        .expect("Failed to write tee info hash to file!\n");
    log::info!(
        "* Tee hash info binary file {} is generated",
        &config.output.display()
    );

    Ok(())
}

// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[macro_use]
extern crate clap;
use log::{error, LevelFilter};
use std::path::PathBuf;
use std::str::FromStr;
use std::vec::Vec;
use std::{env, io, path::Path};
use td_shim_tools::enroller::{create_key_file, enroll_files, FirmwareRawFile};
use td_shim_tools::InputData;
use td_uefi_pi::pi::guid;
const TDSHIM_SB_NAME: &str = "final.sb.bin";

struct Config {
    // Input file path to be read
    pub input: String,
    // Output file path to be written
    pub output: PathBuf,
    // Public key file path
    pub key: Option<String>,
    // Hash algorithm "SHA384" by default
    pub hash_alg: String,
    // Firmware file information to be enrolled into CFV,
    // consists of (Guid, FilePath)
    pub firmware_files: Vec<(guid::Guid, String)>,
    // Log level "SHA384" by default
    pub log_level: String,
}

#[derive(Debug)]
pub enum ConfigParseError {
    InvlidGuid,
    InvalidLogLevel,
    InvalidInputFilePath,
}

impl Config {
    pub fn new() -> Result<Self, ConfigParseError> {
        let matches = command!()
            .arg(
                arg!([tdshim] "shim binary file")
                    .required(true)
                    .allow_invalid_utf8(false),
            )
            .arg(
                arg!(-k --key "public key file for enrollment")
                    .required(false)
                    .takes_value(true)
                    .allow_invalid_utf8(false),
            )
            .arg(
                arg!(-H --hash "hash algorithm to compute digest")
                    .required(false)
                    .takes_value(true)
                    .default_value("SHA384"),
            )
            .arg(
                arg!(-f --file "<Guid> <FilePath> Firmware file to be enrolled into CFV")
                    .required(false)
                    .multiple_values(true)
                    .multiple_occurrences(true)
                    .takes_value(true)
                    .allow_invalid_utf8(false),
            )
            .arg(
                arg!(-l --"log-level" "logging level: [off, error, warn, info, debug, trace]")
                    .required(false)
                    .default_value("info"),
            )
            .arg(
                arg!(-o --output "output of the enrolled shim binary file")
                    .required(false)
                    .takes_value(true)
                    .allow_invalid_utf8(false),
            )
            .get_matches();

        // Safe to unwrap() because they are mandatory or have default values.
        //
        // rust-td binary file
        let input = matches.value_of("tdshim").unwrap().to_string();
        let output = match matches.value_of("output") {
            Some(v) => Path::new(v).to_path_buf(),
            None => {
                let p = Path::new(input.as_str())
                    .canonicalize()
                    .map_err(|_| ConfigParseError::InvalidInputFilePath)?;
                p.parent().unwrap_or(Path::new("/")).join(TDSHIM_SB_NAME)
            }
        };
        let hash_alg = String::from_str(matches.value_of("hash").unwrap()).unwrap();
        let key = match matches.value_of("key") {
            Some(v) => Some(v.to_string()),
            None => None,
        };

        let firmware_files = match matches.values_of("file") {
            Some(inputs) => {
                let inputs = inputs.collect::<Vec<&str>>();
                let mut firmware_files: Vec<(guid::Guid, String)> = Vec::new();
                for i in 0..(inputs.len() / 2) {
                    firmware_files.push((
                        // Guid
                        guid::Guid::from_str(inputs[i * 2])
                            .map_err(|_| ConfigParseError::InvlidGuid)?,
                        // File path
                        inputs[i * 2 + 1].to_string(),
                    ));
                }
                firmware_files
            }
            None => Vec::new(),
        };

        // Safe to unwrap() because they are mandatory or have default values.
        let log_level = String::from_str(matches.value_of("log-level").unwrap())
            .map_err(|_| ConfigParseError::InvalidLogLevel)?;

        Ok(Self {
            input,
            output,
            hash_alg,
            key,
            firmware_files,
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

    // Convert input files as firmware file format
    let ffs = create_firmware_files(&config)?;
    // Enroll the files into CFV
    enroll_files(config.input.as_str(), config.output, ffs)?;

    Ok(())
}

// Build firmware files according to command line input
// 0 / 1 public key file to be enrolled
// 0 ~ n raw file read from system path to be enrolled
fn create_firmware_files(config: &Config) -> io::Result<Vec<FirmwareRawFile>> {
    let mut files: Vec<FirmwareRawFile> = Vec::new();

    if let Some(key) = &config.key {
        let ff_sb = create_key_file(key.as_str(), config.hash_alg.as_str())?;
        files.push(ff_sb);
    }

    for (guid, path) in &config.firmware_files {
        // Create a firmware file
        let mut f = FirmwareRawFile::new(guid.as_bytes());
        let data = InputData::new(path, 1..=1024 * 1024, "firmware file")?;
        f.append(data.as_bytes());
        files.push(f)
    }

    Ok(files)
}

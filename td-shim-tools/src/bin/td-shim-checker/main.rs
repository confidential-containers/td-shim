// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[macro_use]
extern crate clap;
use log::{error, LevelFilter};
use std::str::FromStr;
use std::vec::Vec;
use std::{env, io};
use td_layout::metadata::{TdxMetadataDescriptor, TdxMetadataSection};
use td_shim_tools::loader::TdShimLoader;

struct Config {
    // Input file path to be read
    pub input: String,
    // Log level "SHA384" by default
    pub log_level: String,
}

#[derive(Debug)]
pub enum ConfigParseError {
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
                arg!(-l --"log-level" "logging level: [off, error, warn, info, debug, trace]")
                    .required(false)
                    .default_value("info"),
            )
            .get_matches();

        // Safe to unwrap() because they are mandatory or have default values.
        //
        // rust-td binary file
        let input = matches.value_of("tdshim").unwrap().to_string();

        // Safe to unwrap() because they are mandatory or have default values.
        let log_level = String::from_str(matches.value_of("log-level").unwrap())
            .map_err(|_| ConfigParseError::InvalidLogLevel)?;

        Ok(Self { input, log_level })
    }
}

fn dump_tdx_metadata(
    metadata_descriptor: &TdxMetadataDescriptor,
    metadata_sections: &Vec<TdxMetadataSection>,
) {
    println!("TdxMetadata version: {}", metadata_descriptor.version);
    println!(
        "Number of Sections : {}",
        metadata_descriptor.number_of_section_entry
    );
    println!("-----------------------------------------");
    let mut i = 0;
    loop {
        let section = metadata_sections[i];
        println!(
            "Section {0} - {1}",
            i,
            TdxMetadataSection::get_type_name(section.r#type).unwrap()
        );
        println!("  type            : {:X}", section.r#type);
        println!("  data_offset     : {:X}", section.data_offset);
        println!("  raw_data_size   : {:X}", section.raw_data_size);
        println!("  memory_address  : {:X}", section.memory_address);
        println!("  memory_data_size: {:X}", section.memory_data_size);
        println!("  attributes      : {:X}", section.attributes);

        i += 1;
        if i == metadata_descriptor.number_of_section_entry as usize {
            break;
        }
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

    println!(
        "Parse td-shim binary [{}] to get TdxMetadata ...",
        config.input
    );
    let tdx_metadata = TdShimLoader::parse(&config.input);
    if tdx_metadata.is_none() {
        println!(
            "Failed to parse td-shim binary [{}] to get TdxMetadata",
            config.input
        );
    } else {
        let tdx_metadata = tdx_metadata.unwrap();
        println!(
            "Successfully parse td-shim binary [{}] to get TdxMetadata",
            config.input
        );
        dump_tdx_metadata(&tdx_metadata.0, &tdx_metadata.1);
    }

    Ok(())
}

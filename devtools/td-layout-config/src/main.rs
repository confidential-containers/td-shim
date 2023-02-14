// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use td_layout_config::{image, memory};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ConfigType {
    /// Memory layout config
    Memory,
    /// Image layout config
    Image,
}

#[derive(Parser)]
#[clap(version)]
struct Cli {
    /// Memory config file pathname.
    config: String,
    /// Specify config file type, e.g. json, layout-config
    #[clap(short = 't', long = "config_type", value_enum)]
    config_type: ConfigType,
    /// Memory base address.
    #[clap(short = 'b', long = "base", default_value_t = String::from("0x0"))]
    base: String,
    /// Output to file
    #[clap(short = 'o', long = "output")]
    output: Option<String>,
    /// Output to stdout
    #[clap(short = 'p', long = "print", parse(from_flag))]
    print_flag: bool,
}

fn main() {
    let cli = Cli::parse();

    let config = std::fs::read_to_string(cli.config.to_string())
        .expect("Content is configuration file is invalid");

    let output_file = cli.output.as_ref().map(|path| PathBuf::from(&path));

    match cli.config_type {
        ConfigType::Memory => output(&cli, memory::parse_memory(config), output_file),
        ConfigType::Image => output(&cli, image::parse_image(config), output_file),
    };
}

fn output(cli: &Cli, data: String, dir: Option<PathBuf>) {
    if cli.print_flag {
        print!("{}", data);
    }

    if let Some(path) = dir {
        std::fs::write(path, data.as_bytes()).expect("Failed to create image layout file");
    }
}

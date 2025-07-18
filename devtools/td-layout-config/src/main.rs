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
    /// Top of firmware address (only valid with -t image).
    #[clap(short = 'f', long = "fw_top")]
    fw_top: Option<String>,
    /// Output to file
    #[clap(short = 'o', long = "output")]
    output: Option<String>,
    /// Output to stdout
    #[clap(short = 'p', long = "print")]
    print_flag: bool,
}

fn main() {
    let cli = Cli::parse();

    let config = std::fs::read_to_string(cli.config.to_string())
        .expect("Content is configuration file is invalid");

    let output_file = cli.output.as_ref().map(|path| PathBuf::from(&path));

    const MEMORY_4G: usize = 0x1_0000_0000;
    let mut fw_top = MEMORY_4G;

    if cli.fw_top.is_some() {
        assert!(
            cli.config_type == ConfigType::Image,
            "Top of firmware address is only valid with -t image"
        );
        fw_top = if let Some(fw_top) = cli.fw_top.as_ref().unwrap().strip_prefix("0x") {
            usize::from_str_radix(fw_top, 16)
        } else {
            cli.fw_top.as_ref().unwrap().parse::<usize>()
        }
        .expect("Top of firmware address is invalid.");
        assert!(
            fw_top <= MEMORY_4G,
            "Top of firmware address must be 4GB or below"
        );
        assert!(
            fw_top & 0xfff == 0,
            "Top of firmware adddress must be 4KB aligned"
        );
    }

    match cli.config_type {
        ConfigType::Memory => output(&cli, memory::parse_memory(config), output_file),
        ConfigType::Image => output(&cli, image::parse_image(config, fw_top), output_file),
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

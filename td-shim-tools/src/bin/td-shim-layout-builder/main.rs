// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::{Parser, ValueEnum};
use td_shim_tools::layout_builder::{self, parse_json, parse_layout_config, MemoryRegions};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ConfigType {
    /// json format config
    JSON,
    /// json compatible with td-layout-config
    LayoutConfig,
}

#[derive(Parser)]
#[clap(version)]
struct Cli {
    /// Memory config file pathname.
    config: String,
    /// Specify config file type, e.g. json, layout-config
    #[clap(short = 't', long = "config_type", value_enum, default_value_t = ConfigType::LayoutConfig)]
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

    let base = usize::from_str_radix(cli.base.trim_start_matches("0x"), 16)
        .expect("input address is not valid");
    let memory_regions = MemoryRegions::new(base);

    let memory_regions = match cli.config_type {
        ConfigType::JSON => parse_json::parse_memory(memory_regions, cli.config),
        ConfigType::LayoutConfig => parse_layout_config::parse_memory(memory_regions, cli.config),
    };

    let ret = layout_builder::render(&memory_regions).expect("Render memory layout failed!");

    if cli.print_flag {
        print!("{}", ret);
    }

    if cli.output.is_some() {
        let output = cli.output.unwrap();
        std::fs::write(output, &ret).expect("write file error")
    }
}

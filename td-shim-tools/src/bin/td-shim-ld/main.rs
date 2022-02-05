// Copyright (c) 2020 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[macro_use]
extern crate clap;

use std::io;
use std::str::FromStr;

use log::LevelFilter;
use td_shim_tools::linker::TdShimLinker;

fn main() -> io::Result<()> {
    use env_logger::Env;
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");
    env_logger::init_from_env(env);

    let matches = command!()
        .about("Link multiple shim objects into shim binary")
        .arg(
            arg!([reset_vector] "Reset_vector binary file")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!([ipl] "Internal payload (IPL) binary file")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!([payload] "Payload binary file")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-l --"log-level" "Logging level: [off, error, warn, info, debug, trace]")
                .required(false)
                .default_value("info"),
        )
        .arg(arg!(-r --"relocate-payload" "Relocate shim payload content").required(false))
        .arg(
            arg!(-o --output "Output of the merged shim binary file")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .get_matches();

    if let Ok(lvl) = LevelFilter::from_str(matches.value_of("log-level").unwrap()) {
        log::set_max_level(lvl);
    }

    let mut builder = TdShimLinker::default();
    if let Some(output_name) = matches.value_of("output") {
        builder.set_output_file(output_name.to_string());
    }
    if matches.is_present("relocate-payload") {
        builder.set_payload_relocation(true);
    }

    // Safe to unwrap() because these are mandatory arguments.
    let reset_name = matches.value_of("reset_vector").unwrap();
    let ipl_name = matches.value_of("ipl").unwrap();
    let payload_name = matches.value_of("payload").unwrap();

    builder.build(reset_name, ipl_name, payload_name)
}

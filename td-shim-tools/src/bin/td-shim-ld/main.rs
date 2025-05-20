// Copyright (c) 2020-2025 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[macro_use]
extern crate clap;

use std::io;
use std::str::FromStr;

use clap::{builder::PossibleValue, ArgAction};
use log::{error, LevelFilter};
use td_shim_tools::linker::{ImageFormat, PayloadType, TdShimLinker};

fn main() -> io::Result<()> {
    use env_logger::Env;
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");
    env_logger::init_from_env(env);

    let matches = command!()
        .about("Link multiple shim objects into shim binary")
        .arg(arg!([reset_vector] "Reset_vector binary file").required(true))
        .arg(arg!([ipl] "Internal payload (IPL) binary file").required(true))
        .arg(
            arg!(-p --payload "Payload binary file")
                .required(false)
                .action(ArgAction::Set),
        )
        .arg(
            arg!(-i --"image-format" "Image format")
                .required(false)
                .value_parser([
                    PossibleValue::new("tdvf").help("Generate image in TDVF format"),
                    PossibleValue::new("igvm").help("Generate image in IGVM format"),
                ])
                .default_value("tdvf")
                .action(ArgAction::Set),
        )
        .arg(
            arg!(-t --"payload-type" "Type of payload to be launched by td-shim")
                .required(false)
                .value_parser([
                    PossibleValue::new("linux")
                        .help("Payload Binary is bzImage or vmlinux, follow Linux boot protocol"),
                    PossibleValue::new("executable")
                        .help("Payload Binary is a PE/COFF or ELF executable image as payload"),
                ])
                .default_value("linux")
                .action(ArgAction::Set),
        )
        .arg(
            arg!(-m --metadata "Metadata sections config file")
                .required(false)
                .action(ArgAction::Set),
        )
        .arg(
            arg!(-l --"log-level" "Logging level: [off, error, warn, info, debug, trace]")
                .required(false)
                .default_value("info")
                .action(ArgAction::Set),
        )
        .arg(
            arg!(-r --"relocate-payload" "Relocate shim payload content")
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(-o --output "Output of the merged shim binary file")
                .required(false)
                .action(ArgAction::Set),
        )
        .get_matches();

    if let Ok(lvl) = LevelFilter::from_str(matches.get_one::<String>("log-level").unwrap()) {
        log::set_max_level(lvl);
    }

    let mut builder = TdShimLinker::default();
    if let Some(output_name) = matches.get_one::<String>("output") {
        builder.set_output_file(output_name.clone());
    }

    let image_format = matches.get_one::<String>("image-format").unwrap().as_str();
    ImageFormat::from_str(image_format)
        .map(|i| builder.set_image_format(i))
        .map_err(|_e| {
            error!("Invalid image format {}", image_format);
            io::Error::new(io::ErrorKind::Other, "Invalid image format")
        })?;

    if matches.get_flag("relocate-payload") {
        builder.set_payload_relocation(true);
    }

    let payload_type = matches.get_one::<String>("payload-type").unwrap().as_str();
    PayloadType::from_str(payload_type)
        .map(|t| builder.set_payload_type(t))
        .map_err(|_e| {
            error!("Invalid payload type {}", payload_type);
            io::Error::new(io::ErrorKind::Other, "Invalid payload type")
        })?;

    // Safe to unwrap() because these are mandatory arguments.
    let reset_name = matches.get_one::<String>("reset_vector").unwrap().as_str();
    let ipl_name = matches.get_one::<String>("ipl").unwrap().as_str();
    let payload_name = matches.get_one::<String>("payload").map(|s| s.as_str());
    let metadata_name = matches.get_one::<String>("metadata").map(|s| s.as_str());

    builder.build(reset_name, ipl_name, payload_name, metadata_name)
}

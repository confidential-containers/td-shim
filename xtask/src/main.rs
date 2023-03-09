// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod build;

use std::process::exit;

use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Program {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Image(build::BuildArgs),
}

fn main() {
    match Program::parse().command {
        Commands::Image(args) => match args.build() {
            Ok(image) => {
                println!("Successfully generate TD-Shim image: {}", image.display());
            }
            Err(e) => {
                eprintln!("[ERROR]: {}", e);
                exit(-1)
            }
        },
    };
}

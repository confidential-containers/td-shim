// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[macro_use]
extern crate clap;

use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::FromStr;
use std::vec::Vec;
use std::{env, io, path::Path};

use log::{error, trace, LevelFilter};
use ring::digest;
use td_layout::build_time::{TD_SHIM_CONFIG_OFFSET, TD_SHIM_FIRMWARE_SIZE};
use td_shim_enroll_key::public_key::{
    RsaPublicKeyInfo, SubjectPublicKeyInfo, ID_EC_PUBKEY_OID, RSA_PUBKEY_OID, SECP384R1_OID,
};
use td_shim_enroll_key::{
    build_cfv_ffs_header, build_cfv_header, CfvPubKeyFileHeader, CFV_FILE_HEADER_PUBKEY_GUID,
    PUBKEY_FILE_STRUCT_VERSION_V1, PUBKEY_HASH_ALGORITHM_SHA384,
};
use td_shim_ld::linker::{InputData, OutputFile};

const TDSHIM_SB_NAME: &str = "final.sb.bin";

fn enroll_key(
    tdshim_file: &str,
    key_file: &str,
    output_file: PathBuf,
    hash_alg: &'static digest::Algorithm,
) -> io::Result<()> {
    let tdshim_bin = InputData::new(
        tdshim_file,
        TD_SHIM_FIRMWARE_SIZE as usize..=TD_SHIM_FIRMWARE_SIZE as usize,
        "shim binary",
    )?;
    let key_data = InputData::new(key_file, 1..=1024 * 1024, "public key")?;
    let key = SubjectPublicKeyInfo::try_from(key_data.as_bytes()).map_err(|e| {
        error!("Can not load key from file {}: {}", key_file, e);
        io::Error::new(io::ErrorKind::Other, "invalid key data")
    })?;

    let mut public_bytes: Vec<u8> = Vec::new();
    match key.algorithm.algorithm {
        ID_EC_PUBKEY_OID => {
            if let Some(curve) = key.algorithm.parameters {
                if curve.as_bytes() != SECP384R1_OID.as_bytes() {
                    error!("Unsupported Named Curve from file {}", key_file);
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "unsupported Named Curve",
                    ));
                }
                if key.subject_public_key.as_bytes()[0] != 0x04 {
                    error!("Invalid SECP384R1 public key from file {}", key_file);
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Invalid SECP384R1 public key",
                    ));
                }
                public_bytes.extend_from_slice(&key.subject_public_key.as_bytes()[1..]);
            } else {
                error!("Invalid algorithm parameter from file {}", key_file);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid key algorithm parameter",
                ));
            }
        }
        RSA_PUBKEY_OID => {
            let pubkey =
                RsaPublicKeyInfo::try_from(key.subject_public_key.as_bytes()).map_err(|e| {
                    error!("Invalid key from file {}: {}", key_file, e);
                    io::Error::new(io::ErrorKind::Other, "invalid key from file")
                })?;
            public_bytes.extend_from_slice(pubkey.modulus.as_bytes());
            let mut exp_bytes = [0u8; 8];
            if pubkey.exponents.as_bytes().len() > 8 {
                error!("Invalid exponent size from key file {}", key_file);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid exponent size",
                ));
            }
            exp_bytes[8 - pubkey.exponents.as_bytes().len()..]
                .copy_from_slice(pubkey.exponents.as_bytes());
            public_bytes.extend_from_slice(&exp_bytes);
        }
        t => {
            error!("Unsupported key type {} from file {}", t, key_file);
            return Err(io::Error::new(io::ErrorKind::Other, "unsupported key type"));
        }
    }

    let hash = digest::digest(hash_alg, public_bytes.as_slice());
    let hash = hash.as_ref();

    //Build public key header in CFV
    let pub_key_header = CfvPubKeyFileHeader {
        type_guid: *CFV_FILE_HEADER_PUBKEY_GUID.as_bytes(),
        struct_version: PUBKEY_FILE_STRUCT_VERSION_V1,
        length: (36 + hash.len()) as u32,
        hash_algorithm: PUBKEY_HASH_ALGORITHM_SHA384,
        reserved: 0,
    };

    // Create and write the td-shim binary with key enrolled.
    let mut output = OutputFile::new(output_file)?;
    let cfv_header = build_cfv_header();
    let cfv_ffs_header = build_cfv_ffs_header();

    output.seek_and_write(0, tdshim_bin.as_bytes(), "enrolled shim binary")?;
    output.seek_and_write(
        TD_SHIM_CONFIG_OFFSET as u64,
        cfv_header.as_bytes(),
        "firmware volume header",
    )?;
    output.write(cfv_ffs_header.as_bytes(), "firmware volume fs header")?;
    output.write(pub_key_header.as_bytes(), "firmware key")?;
    output.write(hash, "firmware hash value")?;
    output.flush()?;

    Ok(())
}

fn main() -> io::Result<()> {
    use env_logger::Env;
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");
    env_logger::init_from_env(env);

    let matches = app_from_crate!()
        .arg(
            arg!([tdshim] "shim binary file")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!([key] "key file for enrollment")
                .required(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            arg!(-H --hash "hash algorithm to compute digest")
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
            arg!(-o --output "output of the enrolled shim binary file")
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
                error!("Invalid tdshim file path {}: {}", tdshim_file, e);
                e
            })?;
            p.parent().unwrap_or(Path::new("/")).join(TDSHIM_SB_NAME)
        }
    };

    trace!(
        "\nrust-tdpayload-signing {} {} {} to {}\n",
        tdshim_file,
        key_file,
        hash_alg,
        output_file.display(),
    );

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

    enroll_key(tdshim_file, key_file, output_file, hash_alg)
}

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[macro_use]
extern crate clap;

use std::ptr::slice_from_raw_parts;
use std::str::FromStr;
use std::vec::Vec;
use std::{convert::TryFrom, mem::size_of};
use std::{env, io, path::Path};

use log::{error, trace, LevelFilter};

use r_efi::efi::Guid;
use r_uefi_pi::fv::*;
use ring::digest;
use scroll::{Pread, Pwrite};
use td_layout::build_time::{TD_SHIM_CONFIG_OFFSET, TD_SHIM_CONFIG_SIZE, TD_SHIM_FIRMWARE_SIZE};
use td_shim_ld::{write_u24, FvFfsHeader, FvHeader, InputData, OutputFile};

mod public_key;
use self::public_key::{
    RsaPublicKeyInfo, SubjectPublicKeyInfo, ID_EC_PUBKEY_OID, RSA_PUBKEY_OID, SECP384R1_OID,
};

const CFV_FFS_HEADER_GUID: Guid = Guid::from_fields(
    0x77a2742e,
    0x9340,
    0x4ac9,
    0x8f,
    0x85,
    &[0xb7, 0xb9, 0x78, 0x58, 0x0, 0x21],
); // {77A2742E-9340-4AC9-8F85-B7B978580021}

const FS_DATA_HEADER_GUID: Guid = Guid::from_fields(
    0xbe8f65a3,
    0xa83b,
    0x415c,
    0xa1,
    0xfb,
    &[0xf7, 0x8e, 0x10, 0x5e, 0x82, 0x4e],
); // {BE8F65A3-A83B-415C-A1FB-F78E105E824E}

const PUBKEY_FILE_STRUCT_VERSION: u32 = 0x01;
const TDSHIM_SB_NAME: &str = "final.sb.bin";

#[repr(C, align(4))]
#[derive(Pread, Pwrite)]
struct CfvDataFileHeader {
    pub type_guid: [u8; 16],
    pub struct_version: u32,
    pub length: u32,
    pub hash_algorithm: u64,
    pub reserved: u32,
}

impl CfvDataFileHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

fn build_cfv_header() -> FvHeader {
    let mut cfv_header = FvHeader::default();

    cfv_header
        .fv_header
        .file_system_guid
        .copy_from_slice(FIRMWARE_FILE_SYSTEM3_GUID.as_bytes());
    cfv_header.fv_header.fv_length = TD_SHIM_CONFIG_SIZE as u64;
    cfv_header.fv_header.checksum = 0xdc0a;
    cfv_header.fv_block_map[0].num_blocks = (TD_SHIM_CONFIG_SIZE as u32) / 0x1000;
    cfv_header.fv_block_map[0].length = 0x1000;
    cfv_header.fv_ext_header.ext_header_size = 0x14;

    cfv_header
}

fn build_cfv_ffs_header() -> FvFfsHeader {
    let mut cfv_ffs_header = FvFfsHeader::default();
    cfv_ffs_header
        .ffs_header
        .name
        .copy_from_slice(CFV_FFS_HEADER_GUID.as_bytes());

    cfv_ffs_header.ffs_header.integrity_check = 0xaa4c;
    cfv_ffs_header.ffs_header.r#type = FV_FILETYPE_RAW;
    cfv_ffs_header.ffs_header.attributes = 0x00;
    write_u24(
        TD_SHIM_CONFIG_SIZE - size_of::<FvHeader>() as u32,
        &mut cfv_ffs_header.ffs_header.size,
    );
    cfv_ffs_header.ffs_header.state = 0x07u8;

    cfv_ffs_header
}

fn main() -> std::io::Result<()> {
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

    let tdshim_bin = InputData::new(
        tdshim_file,
        TD_SHIM_FIRMWARE_SIZE as usize..=TD_SHIM_FIRMWARE_SIZE as usize,
        "shim binary",
    )?;
    let key_data = InputData::new(key_file, 1..=1024 * 1024, "private key")?;
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
    let pub_key_header = CfvDataFileHeader {
        type_guid: *FS_DATA_HEADER_GUID.as_bytes(),
        struct_version: PUBKEY_FILE_STRUCT_VERSION,
        length: (36 + hash.len()) as u32,
        hash_algorithm: 1,
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

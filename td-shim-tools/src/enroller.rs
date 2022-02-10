// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::convert::TryFrom;
use std::io;
use std::mem::size_of;
use std::path::PathBuf;
use std::vec::Vec;

use log::error;
use ring::digest;
use td_layout::build_time::{TD_SHIM_CONFIG_OFFSET, TD_SHIM_CONFIG_SIZE, TD_SHIM_FIRMWARE_SIZE};
use td_shim::fv::{FvFfsFileHeader, FvHeader};
use td_shim::secure_boot::{
    CfvPubKeyFileHeader, CFV_FILE_HEADER_PUBKEY_GUID, PUBKEY_FILE_STRUCT_VERSION_V1,
    PUBKEY_HASH_ALGORITHM_SHA384,
};
use uefi_pi::pi::fv::{FIRMWARE_FILE_SYSTEM3_GUID, FV_FILETYPE_RAW};

use crate::public_key::{
    RsaPublicKeyInfo, SubjectPublicKeyInfo, ID_EC_PUBKEY_OID, RSA_PUBKEY_OID, SECP384R1_OID,
};
use crate::{write_u24, InputData, OutputFile};

/// Build a Configure Firmware Volume header for public key hash.
pub fn build_cfv_header() -> FvHeader {
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

/// Build a Configure Firmware Volume Filesystem header for public key hash.
pub fn build_cfv_ffs_header() -> FvFfsFileHeader {
    let mut cfv_ffs_header = FvFfsFileHeader::default();
    cfv_ffs_header
        .ffs_header
        .name
        .copy_from_slice(td_shim::secure_boot::CFV_FFS_HEADER_TRUST_ANCHOR_GUID.as_bytes());

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

/// Enroll a public key into the Configure Firmware Volume of shim binary for secure boot.
///
/// Secure boot in td-shim means the td-shim will verify the digital signature of the payload,
/// based upon a trusted anchor. The payload includes the digital signature and the public key.
/// The td-shim includes a trust anchor - hash of public key.
///
/// Please refer to section "Trust Anchor in Td-Shim" in doc/secure_boot.md for definitions.
pub fn enroll_key(
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

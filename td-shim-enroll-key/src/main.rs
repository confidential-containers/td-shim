// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod public_key;

use crate::public_key::{
    RsaPublicKeyInfo, SubjectPublicKeyInfo, ID_EC_PUBKEY_OID, RSA_PUBKEY_OID, SECP384R1_OID,
};
use core::{convert::TryFrom, mem::size_of};
use r_efi::efi::Guid;
use r_uefi_pi::fv::*;
use ring::digest;
use scroll::{Pread, Pwrite};
use std::vec::Vec;
use std::{env, fs, io::Write, path::Path};
use td_layout::build_time::{TD_SHIM_CONFIG_OFFSET, TD_SHIM_CONFIG_SIZE};

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

#[repr(C)]
#[derive(Copy, Clone, Debug, Pwrite, Default)]
struct CfvHeader {
    fv_header: FirmwareVolumeHeader,
    fv_block_map: [FvBlockMap; 2],
    pad_ffs_header: FfsFileHeader,
    fv_ext_header: FirmwareVolumeExtHeader,
    pad: [u8; 4],
}

#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
struct CfvFfsHeader {
    ffs_header: FfsFileHeader,
}

#[derive(Pread, Pwrite)]
struct CfvDataFileHeader {
    pub type_guid: [u8; 16],
    pub struct_version: u32,
    pub length: u32,
    pub hash_algorithm: u64,
    pub reserved: u32,
}

fn write_u24(data: u32, buf: &mut [u8]) {
    assert_eq!(data < 0xffffff, true);
    buf[0] = (data & 0xFF) as u8;
    buf[1] = ((data >> 8) & 0xFF) as u8;
    buf[2] = ((data >> 16) & 0xFF) as u8;
}

fn build_cfv_header() -> CfvHeader {
    let mut cfv_header = CfvHeader::default();

    cfv_header.fv_header.zero_vector = [0u8; 16];
    cfv_header
        .fv_header
        .file_system_guid
        .copy_from_slice(FIRMWARE_FILE_SYSTEM3_GUID.as_bytes());
    cfv_header.fv_header.fv_length = TD_SHIM_CONFIG_SIZE as u64;
    cfv_header.fv_header.signature = FVH_SIGNATURE;
    cfv_header.fv_header.attributes = 0x0004f6ff;
    cfv_header.fv_header.header_length = 0x0048;
    cfv_header.fv_header.checksum = 0xdc0a;
    cfv_header.fv_header.ext_header_offset = 0x0060;
    cfv_header.fv_header.reserved = 0x00;
    cfv_header.fv_header.revision = 0x02;

    cfv_header.fv_block_map[0].num_blocks = (TD_SHIM_CONFIG_SIZE as u32) / 0x1000;
    cfv_header.fv_block_map[0].length = 0x1000;
    cfv_header.fv_block_map[1].num_blocks = 0x0000;
    cfv_header.fv_block_map[1].length = 0x0000;

    cfv_header.pad_ffs_header.name.copy_from_slice(
        Guid::from_fields(
            0x00000000,
            0x0000,
            0x0000,
            0x00,
            0x00,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        )
        .as_bytes(),
    );
    cfv_header.pad_ffs_header.integrity_check = 0xaae4;
    cfv_header.pad_ffs_header.r#type = FV_FILETYPE_FFS_PAD;
    cfv_header.pad_ffs_header.attributes = 0x00;
    write_u24(0x2c, &mut cfv_header.pad_ffs_header.size);
    cfv_header.pad_ffs_header.state = 0x07u8;

    cfv_header.fv_ext_header.fv_name.copy_from_slice(
        Guid::from_fields(
            0x00000000,
            0x0000,
            0x0000,
            0x00,
            0x00,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        )
        .as_bytes(),
    );
    cfv_header.fv_ext_header.ext_header_size = 0x14;
    cfv_header.pad = [0u8; 4];

    cfv_header
}

fn build_cfv_ffs_header() -> CfvFfsHeader {
    let mut cfv_ffs_header = CfvFfsHeader::default();
    cfv_ffs_header
        .ffs_header
        .name
        .copy_from_slice(CFV_FFS_HEADER_GUID.as_bytes());

    cfv_ffs_header.ffs_header.integrity_check = 0xaa4c;
    cfv_ffs_header.ffs_header.r#type = FV_FILETYPE_RAW;
    cfv_ffs_header.ffs_header.attributes = 0x00;
    write_u24(
        TD_SHIM_CONFIG_SIZE - size_of::<CfvHeader>() as u32,
        &mut cfv_ffs_header.ffs_header.size,
    );
    cfv_ffs_header.ffs_header.state = 0x07u8;

    cfv_ffs_header
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let path_tdshim = &args[1];
    let path_public_key = &args[2];
    let hash_alg = &args[3];

    println!(
        "\nrust-tdpayload-signing {} {} {}\n",
        path_tdshim, path_public_key, hash_alg
    );

    let mut tdshim_bin = fs::read(path_tdshim).expect("fail to read td payload");
    let public_bytes = fs::read(path_public_key).expect("fail to read private key file");

    // Parse public key
    let key = SubjectPublicKeyInfo::try_from(public_bytes.as_slice()).unwrap();

    let mut public_bytes: Vec<u8> = Vec::new();
    match key.algorithm.algorithm {
        ID_EC_PUBKEY_OID => {
            if let Some(curve) = key.algorithm.parameters {
                if curve.as_bytes() != SECP384R1_OID.as_bytes() {
                    panic!("Unsupported Named Curve");
                }
                if key.subject_public_key.as_bytes()[0] != 0x04 {
                    panic!("Invalid SECP384R1 public key");
                }
                public_bytes.extend_from_slice(&key.subject_public_key.as_bytes()[1..]);
            }
        }
        RSA_PUBKEY_OID => {
            let pubkey = RsaPublicKeyInfo::try_from(key.subject_public_key.as_bytes()).unwrap();
            public_bytes.extend_from_slice(pubkey.modulus.as_bytes());
            let mut exp_bytes = [0u8; 8];
            if pubkey.exponents.as_bytes().len() > 8 {
                panic!("Invalid exponent size");
            }
            exp_bytes[8 - pubkey.exponents.as_bytes().len()..]
                .copy_from_slice(pubkey.exponents.as_bytes());
            public_bytes.extend_from_slice(&exp_bytes);
        }
        _ => {
            panic!("Unsupported hash algorithm")
        }
    };

    // Hash public key
    let hash_alg = match hash_alg.as_str() {
        "SHA384" => &digest::SHA384,
        _ => {
            panic!("Unsupported hash algorithm")
        }
    };

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
    let output = Path::new(path_tdshim)
        .parent()
        .unwrap()
        .join(TDSHIM_SB_NAME);
    let mut signed_tdshim_bin = fs::File::create(output).expect("fail to create final binary");

    let cfv_header = build_cfv_header();
    let cfv_ffs_header = build_cfv_ffs_header();

    let mut offset = TD_SHIM_CONFIG_OFFSET as usize;
    tdshim_bin.gwrite(cfv_header, &mut offset).unwrap();
    tdshim_bin.gwrite(cfv_ffs_header, &mut offset).unwrap();
    tdshim_bin.gwrite(pub_key_header, &mut offset).unwrap();
    tdshim_bin.gwrite(hash, &mut offset).unwrap();

    signed_tdshim_bin
        .write_all(&tdshim_bin)
        .expect("fail to write final binary");
    signed_tdshim_bin.sync_data()?;

    Ok(())
}

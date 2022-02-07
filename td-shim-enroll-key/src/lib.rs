// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(feature = "enroller"), no_std)]

use core::mem::size_of;
use core::ptr::slice_from_raw_parts;

use r_efi::efi::Guid;
use scroll::{Pread, Pwrite};
use td_layout::build_time::TD_SHIM_CONFIG_SIZE;
use td_shim_ld::{write_u24, FvFfsHeader, FvHeader};
use uefi_pi::pi::fv::{FIRMWARE_FILE_SYSTEM3_GUID, FV_FILETYPE_RAW};

#[cfg(feature = "enroller")]
pub mod public_key;

/// GUID for trust anchor in the Configuration Firmware Volume (CFV).
///
/// Please refer to doc/secure_boot.md for definition.
pub const CFV_FFS_HEADER_TRUST_ANCHOR_GUID: Guid = Guid::from_fields(
    0x77a2742e,
    0x9340,
    0x4ac9,
    0x8f,
    0x85,
    &[0xb7, 0xb9, 0x78, 0x58, 0x0, 0x21],
); // {77A2742E-9340-4AC9-8F85-B7B978580021}

/// GUID for pubkey hash file in the Configuration Firmware Volume (CFV).
///
/// Please refer to doc/secure_boot.md for definition.
pub const CFV_FILE_HEADER_PUBKEY_GUID: Guid = Guid::from_fields(
    0xbe8f65a3,
    0xa83b,
    0x415c,
    0xa1,
    0xfb,
    &[0xf7, 0x8e, 0x10, 0x5e, 0x82, 0x4e],
); // {BE8F65A3-A83B-415C-A1FB-F78E105E824E}

pub const PUBKEY_FILE_STRUCT_VERSION_V1: u32 = 0x01;
pub const PUBKEY_HASH_ALGORITHM_SHA384: u64 = 1;

#[repr(C, align(4))]
#[derive(Debug, Pread, Pwrite)]
pub struct CfvPubKeyFileHeader {
    pub type_guid: [u8; 16],
    pub struct_version: u32,
    pub length: u32,
    pub hash_algorithm: u64,
    pub reserved: u32,
}

impl CfvPubKeyFileHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

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

pub fn build_cfv_ffs_header() -> FvFfsHeader {
    let mut cfv_ffs_header = FvFfsHeader::default();
    cfv_ffs_header
        .ffs_header
        .name
        .copy_from_slice(CFV_FFS_HEADER_TRUST_ANCHOR_GUID.as_bytes());

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

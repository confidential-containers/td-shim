// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Constants and structs to enable secure boot for td-shim.
//!
//! A customized secure boot protocol is designed for td-shim, please refer to `doc/secure_boot.md`
//! for details.

use core::mem::size_of;
use core::ptr::slice_from_raw_parts;

use r_efi::efi::Guid;
use scroll::{Pread, Pwrite};

/// GUID for secure boot trust anchor in the Configuration Firmware Volume (CFV).
pub const CFV_FFS_HEADER_TRUST_ANCHOR_GUID: Guid = Guid::from_fields(
    0x77a2742e,
    0x9340,
    0x4ac9,
    0x8f,
    0x85,
    &[0xb7, 0xb9, 0x78, 0x58, 0x0, 0x21],
); // {77A2742E-9340-4AC9-8F85-B7B978580021}

/// GUID for secure boot pubkey hash file in the Configuration Firmware Volume (CFV).
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

/// GUID for signed payload.
pub const SIGNED_PAYLOAD_FILE_HEADER_GUID: Guid = Guid::from_fields(
    0xFCF2D558,
    0x9DF5,
    0x4F4D,
    0xB0,
    0xD7,
    &[0x3e, 0x4b, 0x79, 0x8a, 0xb0, 0x66],
); // {FCF2D558-9DF5-4F4D-B0D7-3E4B798AB066}

pub const PAYLOAD_SIGN_ECDSA_NIST_P384_SHA384: u32 = 1;
pub const PAYLOAD_SIGN_RSA_PSS_3072_SHA384: u32 = 2;
pub const PAYLOAD_SIGN_RSA_EXPONENT_SIZE: usize = 8;
pub const PAYLOAD_SIGN_RSA_PUBLIC_KEY_MOD_SIZE: usize = 384;

/// File header for signed payload.
///
/// Please refer to doc/secure_boot.md for definition.
#[repr(C, align(4))]
#[derive(Debug, Pread, Pwrite)]
pub struct PayloadSignHeader {
    pub type_guid: [u8; 16],
    pub struct_version: u32,
    pub length: u32,
    pub payload_version: u64,
    pub payload_svn: u64,
    pub signing_algorithm: u32,
    pub reserved: u32,
}

impl PayloadSignHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            &*core::ptr::slice_from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

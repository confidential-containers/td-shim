// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use core::mem::size_of;
use core::ptr::slice_from_raw_parts;

use r_efi::efi::Guid;
use scroll::{Pread, Pwrite};
use td_layout::build_time::TD_SHIM_RESET_VECTOR_SIZE;
use uefi_pi::pi::fv::{CommonSectionHeader, FfsFileHeader, FV_FILETYPE_RAW, SECTION_RAW};

use crate::write_u24;

/// File header for the ResetVector region.
///
/// The `ResetVectorHeader` is stored at the end of the IPL region, so the total size of the
/// reset vector file is `TD_SHIM_RESET_VECTOR_SIZE + size_of::<ResetVectorHeader>()`.
#[repr(C, align(4))]
#[derive(Debug, Default, Pwrite)]
pub struct ResetVectorHeader {
    pub ffs_header: FfsFileHeader,
    pub section_header_pad: CommonSectionHeader,
    pad: [u8; 8],
    pub section_header_reset_vector: CommonSectionHeader,
}

impl ResetVectorHeader {
    pub fn build_tdx_reset_vector_header() -> Self {
        let mut tdx_reset_vector_header = ResetVectorHeader::default();

        tdx_reset_vector_header.ffs_header.name.copy_from_slice(
            Guid::from_fields(
                0x1ba0062e,
                0xc779,
                0x4582,
                0x85,
                0x66,
                &[0x33, 0x6a, 0xe8, 0xf7, 0x8f, 0x09],
            )
            .as_bytes(),
        );
        tdx_reset_vector_header.ffs_header.integrity_check = 0xaa5a;
        tdx_reset_vector_header.ffs_header.r#type = FV_FILETYPE_RAW;
        tdx_reset_vector_header.ffs_header.attributes = 0x08;
        write_u24(
            TD_SHIM_RESET_VECTOR_SIZE + size_of::<ResetVectorHeader>() as u32,
            &mut tdx_reset_vector_header.ffs_header.size,
        );
        tdx_reset_vector_header.ffs_header.state = 0x07u8;

        write_u24(0x0c, &mut tdx_reset_vector_header.section_header_pad.size);
        tdx_reset_vector_header.section_header_pad.r#type = SECTION_RAW;

        tdx_reset_vector_header.pad = [0u8; 8];

        write_u24(
            TD_SHIM_RESET_VECTOR_SIZE + size_of::<CommonSectionHeader>() as u32,
            &mut tdx_reset_vector_header.section_header_reset_vector.size,
        );
        tdx_reset_vector_header.section_header_reset_vector.r#type = SECTION_RAW;

        tdx_reset_vector_header
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

#[repr(C, align(4))]
#[derive(Debug, Pread, Pwrite)]
pub struct ResetVectorParams {
    pub entry_point: u32, // rust entry point
    pub img_base: u32,    // rust ipl bin base
    pub img_size: u32,    // rust ipl bin size
}

impl ResetVectorParams {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

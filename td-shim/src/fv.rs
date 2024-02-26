// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::mem::size_of;
use core::ptr::slice_from_raw_parts;

use r_efi::efi::Guid;
use scroll::{Pread, Pwrite};
use td_shim_interface::td_uefi_pi::pi::fv::{
    Checksum, CommonSectionHeader, FfsFileHeader, FirmwareVolumeExtHeader, FirmwareVolumeHeader,
    FvBlockMap, FIRMWARE_FILE_SYSTEM2_GUID, FVH_SIGNATURE, FV_FILETYPE_FFS_PAD,
};

use crate::write_u24;

/// Firmware volume header.
#[repr(C, align(4))]
#[derive(Copy, Clone, Debug, Pwrite)]
pub struct FvHeader {
    pub fv_header: FirmwareVolumeHeader,
    pub fv_block_map: [FvBlockMap; 2],
    pub pad_ffs_header: FfsFileHeader,
    pub fv_ext_header: FirmwareVolumeExtHeader,
    pad: [u8; 4],
}

impl FvHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

impl Default for FvHeader {
    fn default() -> Self {
        let mut header_sz = [0u8; 3];
        write_u24(0x2c, &mut header_sz);

        let ffs_checksum = Checksum {
            header: 0x00,
            file: 0x00,
        };

        FvHeader {
            fv_header: FirmwareVolumeHeader {
                zero_vector: [0u8; 16],
                file_system_guid: *FIRMWARE_FILE_SYSTEM2_GUID.as_bytes(),
                fv_length: 0,
                signature: FVH_SIGNATURE,
                attributes: 0x0004f6ff,
                header_length: 0x0048,
                checksum: 0,
                ext_header_offset: 0x0060,
                reserved: 0x00,
                revision: 0x02,
            },
            fv_block_map: [FvBlockMap::default(); 2],
            pad_ffs_header: FfsFileHeader {
                name: *Guid::from_fields(
                    0x00000000,
                    0x0000,
                    0x0000,
                    0x00,
                    0x00,
                    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                )
                .as_bytes(),
                integrity_check: ffs_checksum,
                r#type: FV_FILETYPE_FFS_PAD,
                attributes: 0x00,
                size: header_sz,
                state: 0x07u8,
            },
            fv_ext_header: FirmwareVolumeExtHeader {
                fv_name: [0u8; 16],
                ext_header_size: 0,
            },
            pad: [0u8; 4],
        }
    }
}

/// Firmware volume file header.
#[repr(C, align(4))]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FvFfsFileHeader {
    pub ffs_header: FfsFileHeader,
}

impl FvFfsFileHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// Firmware volume file section header.
#[repr(C, align(4))]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FvFfsSectionHeader {
    pub section_header: CommonSectionHeader,
}

pub type PayloadFvHeader = FvHeader;
pub type PayloadFvFfsHeader = FvFfsFileHeader;
pub type PayloadFvFfsSectionHeader = FvFfsSectionHeader;
pub type IplFvHeader = PayloadFvHeader;
pub type IplFvFfsHeader = PayloadFvFfsHeader;
pub type IplFvFfsSectionHeader = FvFfsSectionHeader;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fv_header() {
        let fv_header = FvHeader::default();
        let _ = fv_header.as_bytes();
    }

    #[test]
    fn test_fvffsfile_header() {
        let hdr = FvFfsFileHeader::default();
        let _ = hdr.as_bytes();
    }

    #[test]
    fn test_fvffssection_header() {
        let _hdr = FvFfsSectionHeader::default();
    }
}

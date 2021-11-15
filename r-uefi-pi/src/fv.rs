// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use r_efi::efi::Guid;

pub type FvbAttributes2 = u32;

pub const FVH_SIGNATURE: u32 = 0x4856465F; // '_','F','V','H'
use scroll::{Pread, Pwrite};

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FirmwareVolumeHeader {
    pub zero_vector: [u8; 16],
    pub file_system_guid: [u8; 16], // Guid
    pub fv_length: u64,
    pub signature: u32,
    pub attributes: FvbAttributes2,
    pub header_length: u16,
    pub checksum: u16,
    pub ext_header_offset: u16,
    pub reserved: u8,
    pub revision: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FvBlockMap {
    pub num_blocks: u32,
    pub length: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FirmwareVolumeExtHeader {
    pub fv_name: [u8; 16], // Guid
    pub ext_header_size: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FirmwareVolumeExtEntry {
    pub ext_entry_size: u16,
    pub ext_entry_type: u32,
}

pub const FIRMWARE_FILE_SYSTEM2_GUID: r_efi::base::Guid = r_efi::base::Guid::from_fields(
    0x8c8ce578,
    0x8a3d,
    0x4f1c,
    0x99,
    0x35,
    &[0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3],
);

pub const FIRMWARE_FILE_SYSTEM3_GUID: r_efi::base::Guid = r_efi::base::Guid::from_fields(
    0x5473c07a,
    0x3dcb,
    0x4dca,
    0xbd,
    0x6f,
    &[0x1e, 0x96, 0x89, 0xe7, 0x34, 0x9a],
);

pub type FvFileType = u8;

pub const FV_FILETYPE_RAW: u8 = 0x01;
pub const FV_FILETYPE_FREEFORM: u8 = 0x02;
pub const FV_FILETYPE_SECURITY_CORE: u8 = 0x03;
pub const FV_FILETYPE_PEI_CORE: u8 = 0x04;
pub const FV_FILETYPE_DXE_CORE: u8 = 0x05;
pub const FV_FILETYPE_PEIM: u8 = 0x06;
pub const FV_FILETYPE_DRIVER: u8 = 0x07;
pub const FV_FILETYPE_COMBINED_PEIM_DRIVER: u8 = 0x08;
pub const FV_FILETYPE_APPLICATION: u8 = 0x09;
pub const FV_FILETYPE_MM: u8 = 0x0A;
pub const FV_FILETYPE_FIRMWARE_VOLUME_IMAGE: u8 = 0x0B;
pub const FV_FILETYPE_COMBINED_MM_DXE: u8 = 0x0C;
pub const FV_FILETYPE_MM_CORE: u8 = 0x0D;
pub const FV_FILETYPE_MM_STANDALONE: u8 = 0x0E;
pub const FV_FILETYPE_MM_CORE_STANDALONE: u8 = 0x0F;
pub const FV_FILETYPE_FFS_PAD: u8 = 0xF0;

pub type FfsFileAttributes = u8;
pub type FfsFileState = u8;

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FfsFileHeader {
    pub name: [u8; 16], // Guid,
    pub integrity_check: u16,
    pub r#type: FvFileType,
    pub attributes: FfsFileAttributes,
    pub size: [u8; 3],
    pub state: FfsFileState,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FfsFileHeader2 {
    pub name: Guid,
    pub integrity_check: u16,
    pub r#type: FvFileType,
    pub attributes: FfsFileAttributes,
    pub size: [u8; 3],
    pub state: FfsFileState,
    pub extended_size: u32,
}

pub type SectionType = u8;

pub const SECTION_ALL: u8 = 0x00;

pub const SECTION_COMPRESSION: u8 = 0x01;
pub const SECTION_GUID_DEFINED: u8 = 0x02;
pub const SECTION_DISPOSABLE: u8 = 0x03;

pub const SECTION_PE32: u8 = 0x10;
pub const SECTION_PIC: u8 = 0x11;
pub const SECTION_TE: u8 = 0x12;
pub const SECTION_DXE_DEPEX: u8 = 0x13;
pub const SECTION_VERSION: u8 = 0x14;
pub const SECTION_USER_INTERFACE: u8 = 0x15;
pub const SECTION_COMPATIBILITY16: u8 = 0x16;
pub const SECTION_FIRMWARE_VOLUME_IMAGE: u8 = 0x17;
pub const SECTION_FREEFORM_SUBTYPE_GUID: u8 = 0x18;
pub const SECTION_RAW: u8 = 0x19;
pub const SECTION_PEI_DEPEX: u8 = 0x1B;
pub const SECTION_MM_DEPEX: u8 = 0x1C;

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct CommonSectionHeader {
    pub size: [u8; 3],
    pub r#type: SectionType,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CommonSectionHeader2 {
    pub size: [u8; 3],
    pub r#type: SectionType,
    pub extended_size: u32,
}

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

//! UEFI-PI storage service.
//!
//! The UEFI storage service is composed of Firmware Volume, Firmware Filesystem, File and Section.
//!
//! A Firmware Volume (FV) is a logical firmware device. In this specification, the basic storage
//! repository for data and/or code is the firmware volume. Each firmware volume is organized into
//! a  file system. As such, the file is the base unit of storage for firmware.
//!
//! A firmware file system (FFS) describes the organization of files and (optionally) free space
//! within the firmware volume. Each firmware file system has a unique GUID, which is used by the
//! firmware to associate a driver with a newly exposed firmware volume.
//!
//! Firmware files are code and/or data stored in firmware volumes. A firmware file may contain
//! multiple sections.
//!
//! Firmware file sections are separate discrete “parts” within certain file types.
use core::mem::size_of;
use core::ptr::slice_from_raw_parts;
use scroll::{Pread, Pwrite};

pub type FvbAttributes2 = u32;
pub const FVH_REVISION: u8 = 2;

// Calculate the 8-bit sum of all elements in a u8 slice
fn sum8(data: &[u8]) -> u8 {
    let mut sum = 0u8;
    let cnt = data.len();
    for item in data.iter().take(cnt) {
        sum = sum.wrapping_add(*item);
    }
    sum
}

// Calculate the 16-bit sum of all elements in a u8 slice
fn sum16(data: &[u8]) -> u16 {
    let mut sum = 0u16;
    let cnt = data.len() / 2;
    for i in 0..cnt {
        sum = sum.wrapping_add((data[i * 2 + 1] as u16) << 8 | data[i * 2] as u16);
    }
    if cnt * 2 == data.len() - 1 {
        sum = sum.wrapping_add(data[cnt * 2] as u16)
    }
    sum
}

/// Firmware volume signature defined in [UEFI-PI] section 3.2.1
pub const FVH_SIGNATURE: u32 = 0x4856465F; // '_','F','V','H'

/// Firmware volume header defined in [UEFI-PI] section "3.2.1 Firmware Volume".
///
/// A firmware volume based on a block device begins with a header that describes the features and
/// layout of the firmware volume. This header includes a description of the capabilities, state,
/// and block map of the device.
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

impl FirmwareVolumeHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    // Calculate and update the checksum of the FirmwareVolumeHeader
    pub fn update_checksum(&mut self) {
        // Clear the existing one before we calculate the chesum
        self.checksum = 0;
        self.checksum = (u16::MAX - sum16(self.as_bytes())).wrapping_add(1);
    }

    // Validate the checksum of the FirmwareVolumeHeader
    pub fn validate_checksum(&self) -> bool {
        sum16(self.as_bytes()) == 0
    }
}

/// Firmware block map.
///
/// The block map is a run-length-encoded array of logical block definitions. This design allows a
/// reasonable mechanism of describing the block layout of typical firmware devices. Each block can
/// be referenced by its logical block address (LBA). The LBA is a zero-based enumeration of all of
/// the blocks—i.e., LBA 0 is the first block, LBA 1 is the second block, and LBA n is the (n-1)
/// device. The header is always located at the beginning of LBA 0.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FvBlockMap {
    pub num_blocks: u32,
    pub length: u32,
}

impl FvBlockMap {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// Firmware Volume Extended Header pointed to by `FirmwareVolumeHeader::ext_header_offset`.
///
/// The extended header is followed by zero or more variable length extension entries.
/// Each extension entry is prefixed with the EFI_FIRMWARE_VOLUME_EXT_ENTRY structure, which
/// defines the type and size of the extension entry. The extended header is always 32-bit aligned
/// relative to the start of the FIRMWARE VOLUME.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FirmwareVolumeExtHeader {
    pub fv_name: [u8; 16], // Guid
    pub ext_header_size: u32,
}

impl FirmwareVolumeExtHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// Firmware volume extension entry.
///
/// After the extension header, there is an array of variable-length extension header entries,
/// each prefixed with the EFI_FIRMWARE_VOLUME_EXT_ENTRY structure.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FirmwareVolumeExtEntry {
    pub ext_entry_size: u16,
    pub ext_entry_type: u32,
}

impl FirmwareVolumeExtEntry {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// EFI_FIRMWARE_FILE_SYSTEM2_GUID defined in [UEFI-PI Spec], section 3.2.2
pub const FIRMWARE_FILE_SYSTEM2_GUID: r_efi::base::Guid = r_efi::base::Guid::from_fields(
    0x8c8ce578,
    0x8a3d,
    0x4f1c,
    0x99,
    0x35,
    &[0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3],
);

/// EFI_FIRMWARE_FILE_SYSTEM3_GUID defined in [UEFI-PI Spec], section 3.2.2
pub const FIRMWARE_FILE_SYSTEM3_GUID: r_efi::base::Guid = r_efi::base::Guid::from_fields(
    0x5473c07a,
    0x3dcb,
    0x4dca,
    0xbd,
    0x6f,
    &[0x1e, 0x96, 0x89, 0xe7, 0x34, 0x9a],
);

/// Firmware File Types defined in [UEFI-PI], section 2.1.4.1
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

//
// FFS File Attributes.
//
pub const FFS_ATTRIB_LARGE_FILE: u8 = 0x01;
pub const FFS_ATTRIB_DATA_ALIGNMENT2: u8 = 0x02;
pub const FFS_ATTRIB_FIXED: u8 = 0x04;
pub const FFS_ATTRIB_DATA_ALIGNMENT: u8 = 0x38;
pub const FFS_ATTRIB_CHECKSUM: u8 = 0x40;
//
// FFS_FIXED_CHECKSUM is the checksum value used when the
// FFS_ATTRIB_CHECKSUM attribute bit is clear
//
pub const FFS_FIXED_CHECKSUM: u8 = 0xAA;

// FFS File State Bits
pub const EFI_FILE_HEADER_CONSTRUCTION: u8 = 0x01;
pub const EFI_FILE_HEADER_VALID: u8 = 0x02;
pub const EFI_FILE_DATA_VALID: u8 = 0x04;
pub const EFI_FILE_MARKED_FOR_UPDATE: u8 = 0x08;
pub const EFI_FILE_DELETED: u8 = 0x10;
pub const EFI_FILE_HEADER_INVALID: u8 = 0x20;

pub type FfsFileAttributes = u8;
pub type FfsFileState = u8;

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct Checksum {
    pub header: u8,
    pub file: u8,
}

/// File Header for files smaller than 16Mb, define in [UEFI-PI Spec] section 2.2.3
///
/// All FFS files begin with a header that is aligned on an 8-byteboundry with respect to the
/// beginning of the firmware volume. FFS files can contain the following parts: Header and Data.
/// It is possible to create a file that has only a header and no data, which consumes 24 bytes
/// of space. This type of file is known as a zero-length file. If the file contains data,
/// the data immediately follows the header. The format of the data within a file is defined by the
/// Type field in the header, either EFI_FFS_FILE_HEADER or EFI_FFS_FILE_HEADER2.
/// If the file length is bigger than 16MB, EFI_FFS_FILE_HEADER2 must be used.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FfsFileHeader {
    pub name: [u8; 16], // Guid,
    pub integrity_check: Checksum,
    pub r#type: FvFileType,
    pub attributes: FfsFileAttributes,
    pub size: [u8; 3],
    pub state: FfsFileState,
}

impl FfsFileHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    // Calculate and update the checksum of the FfsFileHeader
    pub fn update_checksum(&mut self) {
        // Clear the existing one before we calculate the checksum
        self.integrity_check.header = 0;
        self.integrity_check.file = 0;
        self.state = 0;
        self.integrity_check.header = (u8::MAX - sum8(self.as_bytes())).wrapping_add(1);

        self.integrity_check.file = FFS_FIXED_CHECKSUM;
        self.state = EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID | EFI_FILE_DATA_VALID;
    }

    // Validate the checksum of the FfsFileHeader
    pub fn validate_checksum(&self) -> bool {
        ffs_header_validate_checksum(self.as_bytes())
    }
}

/// File Header 2 for files larger than 16Mb, define in [UEFI-PI Spec] section 2.2.3
///
/// All FFS files begin with a header that is aligned on an 8-byteboundry with respect to the
/// beginning of the firmware volume. FFS files can contain the following parts: Header and Data.
/// It is possible to create a file that has only a header and no data, which consumes 24 bytes
/// of space. This type of file is known as a zero-length file. If the file contains data,
/// the data immediately follows the header. The format of the data within a file is defined by the
/// Type field in the header, either EFI_FFS_FILE_HEADER or EFI_FFS_FILE_HEADER2.
/// If the file length is bigger than 16MB, EFI_FFS_FILE_HEADER2 must be used.
#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct FfsFileHeader2 {
    pub name: [u8; 16], // Guid,
    pub integrity_check: Checksum,
    pub r#type: FvFileType,
    pub attributes: FfsFileAttributes,
    pub size: [u8; 3],
    pub state: FfsFileState,
    pub extended_size: u32,
}

impl FfsFileHeader2 {
    // Calculate and update the checksum of the FfsFileHeader
    pub fn update_checksum(&mut self) {
        // Clear the existing one before we calculate the checksum
        self.integrity_check.header = 0;
        self.integrity_check.file = 0;
        self.state = 0;
        self.integrity_check.header = (u8::MAX - sum8(self.as_bytes())).wrapping_add(1);

        self.integrity_check.file = FFS_FIXED_CHECKSUM;
        self.state = EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID | EFI_FILE_DATA_VALID;
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    // Validate the checksum of the FfsFileHeader
    pub fn validate_checksum(&self) -> bool {
        ffs_header_validate_checksum(self.as_bytes())
    }
}

fn ffs_header_validate_checksum(bytes: &[u8]) -> bool {
    let sum = sum8(bytes);
    sum ^ ((EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID | EFI_FILE_DATA_VALID)
        + FFS_FIXED_CHECKSUM)
        == 0
}

/// Firmware File Section Types defined in [UEFI-PI], section 2.1.5.1
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

/// Section Header for files smaller than 16Mb, define in [UEFI-PI Spec] section 2.2.4
#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct CommonSectionHeader {
    pub size: [u8; 3],
    pub r#type: SectionType,
}

impl CommonSectionHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// Section Header 2 for files larger than 16Mb, define in [UEFI-PI Spec] section 2.2.4
#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
pub struct CommonSectionHeader2 {
    pub size: [u8; 3],
    pub r#type: SectionType,
    pub extended_size: u32,
}

impl CommonSectionHeader2 {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fvh_checksum() {
        let mut header = FirmwareVolumeHeader::default();
        header.attributes = 0x4feff;
        header.revision = FVH_REVISION;
        header.signature = FVH_SIGNATURE;
        header.header_length = size_of::<FirmwareVolumeHeader>() as u16;
        header.fv_length = 0x1000;
        header.checksum = 0x3fef;
        header.update_checksum();

        assert_eq!(header.checksum, 0x6010);
        assert!(header.validate_checksum());

        header.checksum = 0x3fe6;
        assert!(!header.validate_checksum());

        header.update_checksum();
        assert_eq!(header.checksum, 0x6010);
        assert!(header.validate_checksum());
    }

    #[test]
    fn test_ffsh_checksum() {
        let mut header = FfsFileHeader::default();
        header.r#type = FV_FILETYPE_FFS_PAD;

        header.update_checksum();
        assert_eq!(header.integrity_check.header, 0x10);
        assert!(ffs_header_validate_checksum(header.as_bytes()));

        header.name = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert!(!ffs_header_validate_checksum(header.as_bytes()));
        header.update_checksum();
        assert_eq!(header.integrity_check.header, 0xC);
        assert!(ffs_header_validate_checksum(header.as_bytes()));
    }

    #[test]
    fn test_update_checksum() {
        let mut header = FfsFileHeader::default();
        header.update_checksum();

        let mut header = FirmwareVolumeHeader::default();
        header.update_checksum();
    }
}

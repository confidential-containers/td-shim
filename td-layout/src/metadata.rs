// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::ptr::slice_from_raw_parts;
use scroll::{Pread, Pwrite};

const TDX_METADATA_GUID1: u32 = 0xe9eaf9f3;
const TDX_METADATA_GUID2: u32 = 0x44d5168e;
const TDX_METADATA_GUID3: u32 = 0x4d7feba8;
const TDX_METADATA_GUID4: u32 = 0xaef63887;

const TDX_METADATA_SIGNATURE: u32 = 0x46564454;

/// Section type for EFI Boot Firmware Volume.
pub const TDX_METADATA_SECTION_TYPE_BFV: u32 = 0;
/// Section type for EFI Boot Configuration Volume.
pub const TDX_METADATA_SECTION_TYPE_CFV: u32 = 1;
/// Section type for EFI Hand-off Blob.
pub const TDX_METADATA_SECTION_TYPE_TD_HOB: u32 = 2;
/// Section type for stack, heap and mailbox.
pub const TDX_METADATA_SECTION_TYPE_TEMP_MEM: u32 = 3;
/// Section type for kernel image.
pub const TDX_METADATA_SECTION_TYPE_PAYLOAD: u32 = 5;
/// Section type for kernel parameters.
pub const TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM: u32 = 6;

/// Attribute flags for BFV.
pub const TDX_METADATA_ATTRIBUTES_EXTENDMR: u32 = 0x00000001;

#[repr(C)]
#[derive(Pread, Pwrite)]
pub struct TdxMetadataDescriptor {
    pub signature: u32,
    pub length: u32,
    pub version: u32,
    pub number_of_section_entry: u32,
}

impl Default for TdxMetadataDescriptor {
    fn default() -> Self {
        TdxMetadataDescriptor {
            signature: TDX_METADATA_SIGNATURE,
            length: 16,
            version: 1,
            number_of_section_entry: 0,
        }
    }
}

impl TdxMetadataDescriptor {
    pub fn set_sections(&mut self, sections: u32) {
        // TdxMetadataDescriptor.length does not include TdxMetadata.guid, so "16 + 32 * sections"
        // instead of "32 + 32 * sections".
        assert!(sections < 0x10000);
        self.number_of_section_entry = sections;
        self.length = 16 + sections * 32;
    }

    pub fn is_valid(&self) -> bool {
        let len = self.length;

        !(self.signature != TDX_METADATA_SIGNATURE
            || self.version != 1
            || self.number_of_section_entry == 0
            || len < 16
            || (len - 16) % 32 != 0
            || (len - 16) / 32 != self.number_of_section_entry)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Pwrite, Pread)]
pub struct TdxMetadataSection {
    pub data_offset: u32,
    pub raw_data_size: u32,
    pub memory_address: u64,
    pub memory_data_size: u64,
    pub r#type: u32,
    pub attributes: u32,
}

#[repr(C)]
#[derive(Pwrite, Pread)]
pub struct TdxMetadataGuid {
    pub data1: u32,
    pub data2: u32,
    pub data3: u32,
    pub data4: u32,
}

impl TdxMetadataGuid {
    /// Check whether it's a valid
    pub fn is_valid(&self) -> bool {
        self.data1 == TDX_METADATA_GUID1
            && self.data2 == TDX_METADATA_GUID2
            && self.data3 == TDX_METADATA_GUID3
            && self.data4 == TDX_METADATA_GUID4
    }
}

impl Default for TdxMetadataGuid {
    fn default() -> Self {
        TdxMetadataGuid {
            data1: TDX_METADATA_GUID1,
            data2: TDX_METADATA_GUID2,
            data3: TDX_METADATA_GUID3,
            data4: TDX_METADATA_GUID4,
        }
    }
}

#[repr(C)]
#[derive(Pwrite)]
pub struct TdxMetadata {
    pub guid: TdxMetadataGuid,
    pub descriptor: TdxMetadataDescriptor,
    /// Sections for BFV, CFV, stack, heap, TD_HOP, Mailbox.
    pub sections: [TdxMetadataSection; 6],
    #[cfg(feature = "boot-kernel")]
    /// Sections for kernel image and parameters.
    pub payload_sections: [TdxMetadataSection; 2],
}

impl Default for TdxMetadata {
    fn default() -> Self {
        let mut data = TdxMetadata {
            guid: Default::default(),
            descriptor: Default::default(),
            sections: [Default::default(); 6],
            #[cfg(feature = "boot-kernel")]
            payload_sections: [Default::default(), 2],
        };

        if cfg!(feature = "boot-kernel") {
            data.descriptor.set_sections(8);
        } else {
            data.descriptor.set_sections(6);
        }

        data
    }
}

impl TdxMetadata {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            &*slice_from_raw_parts(
                self as *const TdxMetadata as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[repr(C)]
#[derive(Default, Pwrite, Pread)]
pub struct TdxMetadataPtr {
    pub ptr: u32,
}

impl TdxMetadataPtr {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            &*slice_from_raw_parts(
                self as *const TdxMetadataPtr as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scroll::export::mem::size_of;

    #[test]
    fn ensure_data_struct_size() {
        assert_eq!(size_of::<TdxMetadataDescriptor>(), 16);
        assert_eq!(size_of::<TdxMetadataSection>(), 32);
        assert_eq!(size_of::<TdxMetadataGuid>(), 16);
        assert_eq!(size_of::<TdxMetadataPtr>(), 4);
        #[cfg(not(feature = "boot-kernel"))]
        assert_eq!(size_of::<TdxMetadata>(), 224);
        #[cfg(feature = "boot-kernel")]
        assert_eq!(size_of::<TdxMetadata>(), 256);
    }

    #[test]
    fn test_tdx_metadata_descriptor() {
        let mut desc = TdxMetadataDescriptor::default();

        assert_eq!(desc.signature, TDX_METADATA_SIGNATURE);
        assert_eq!(desc.length, 16);
        assert_eq!(desc.version, 1);
        assert_eq!(desc.number_of_section_entry, 0);
        assert_eq!(desc.is_valid(), false);

        desc.set_sections(1);
        assert_eq!(desc.signature, TDX_METADATA_SIGNATURE);
        assert_eq!(desc.length, 48);
        assert_eq!(desc.version, 1);
        assert_eq!(desc.number_of_section_entry, 1);
        assert_eq!(desc.is_valid(), true);
    }

    #[test]
    fn test_tdx_metadata_guid() {
        let mut guid = TdxMetadataGuid::default();

        assert_eq!(guid.data1, TDX_METADATA_GUID1);
        assert_eq!(guid.data2, TDX_METADATA_GUID2);
        assert_eq!(guid.data3, TDX_METADATA_GUID3);
        assert_eq!(guid.data4, TDX_METADATA_GUID4);
        assert_eq!(guid.is_valid(), true);

        guid.data1 = 0;
        assert_eq!(guid.is_valid(), false);
    }
}

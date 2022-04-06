// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;

use alloc::string::String;
use core::{convert::TryInto, ptr::slice_from_raw_parts, str::FromStr};
use scroll::{Pread, Pwrite};
use td_uefi_pi::pi::guid::Guid;

const TDX_METADATA_GUID_STR: &str = "F3F9EAE9-8E16-D544-A8EB-7F4D8738F6AE";

const TDX_METADATA_SIGNATURE: u32 = 0x46564454;

/// TdxMetadata Offset
pub const TDX_METADATA_OFFSET: u32 = 0x20;

/// TdxMetadata guid length
pub const TDX_METADATA_GUID_LEN: u32 = 16;
/// TdxMetadata description length
pub const TDX_METADATA_DESCRIPTOR_LEN: u32 = 16;
/// TdxMetadata section length
pub const TDX_METADATA_SECTION_LEN: u32 = 32;

/// Section type for EFI Boot Firmware Volume.
pub const TDX_METADATA_SECTION_TYPE_BFV: u32 = 0;
/// Section type for EFI Boot Configuration Volume.
pub const TDX_METADATA_SECTION_TYPE_CFV: u32 = 1;
/// Section type for EFI Hand-off Blob.
pub const TDX_METADATA_SECTION_TYPE_TD_HOB: u32 = 2;
/// Section type for stack, heap and mailbox.
pub const TDX_METADATA_SECTION_TYPE_TEMP_MEM: u32 = 3;
/// Section type for PermMem
pub const TDX_METADATA_SECTION_TYPE_PERM_MEM: u32 = 4;
/// Section type for kernel image.
pub const TDX_METADATA_SECTION_TYPE_PAYLOAD: u32 = 5;
/// Section type for kernel parameters.
pub const TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM: u32 = 6;
/// Max Section type
pub const TDX_METADATA_SECTION_TYPE_MAX: u32 = 7;

pub const TDX_METADATA_SECTION_TYPE_STRS: [&str; TDX_METADATA_SECTION_TYPE_MAX as usize] = [
    "BFV",
    "CFV",
    "TD_HOB",
    "TempMem",
    "PermMem",
    "Payload",
    "PayloadParam",
];

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

    pub fn from_bytes(buffer: &[u8; 16]) -> Option<TdxMetadataDescriptor> {
        let mut metadata_descriptor = TdxMetadataDescriptor::default();

        metadata_descriptor.signature = u32::from_le_bytes(buffer[..4].try_into().unwrap());
        metadata_descriptor.length = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        metadata_descriptor.version = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
        metadata_descriptor.number_of_section_entry =
            u32::from_le_bytes(buffer[12..].try_into().unwrap());

        if metadata_descriptor.is_valid() {
            Some(metadata_descriptor)
        } else {
            return None;
        }
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

impl TdxMetadataSection {
    pub fn get_type_name(r#type: u32) -> Option<String> {
        if r#type >= TDX_METADATA_SECTION_TYPE_MAX {
            None
        } else {
            Some(String::from(
                TDX_METADATA_SECTION_TYPE_STRS[r#type as usize],
            ))
        }
    }

    pub fn from_bytes(buffer: &[u8; 32]) -> Option<TdxMetadataSection> {
        let mut metadata_section = TdxMetadataSection::default();
        metadata_section.data_offset = u32::from_le_bytes(buffer[..4].try_into().unwrap());
        metadata_section.raw_data_size = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        metadata_section.memory_address = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
        metadata_section.memory_data_size = u64::from_le_bytes(buffer[16..24].try_into().unwrap());
        metadata_section.r#type = u32::from_le_bytes(buffer[24..28].try_into().unwrap());
        metadata_section.attributes = u32::from_le_bytes(buffer[28..32].try_into().unwrap());

        if metadata_section.is_valid() {
            Some(metadata_section)
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> bool {
        let mut valid = false;
        match self.r#type {
            TDX_METADATA_SECTION_TYPE_BFV => {
                valid = self.raw_data_size != 0
                    && self.memory_address != 0
                    && self.memory_data_size != 0
                    && self.attributes == TDX_METADATA_ATTRIBUTES_EXTENDMR;
            }

            TDX_METADATA_SECTION_TYPE_CFV => {
                valid = self.raw_data_size != 0
                    && self.memory_address != 0
                    && self.memory_data_size != 0
                    && self.attributes == 0;
            }

            TDX_METADATA_SECTION_TYPE_TD_HOB => {
                valid = self.data_offset == 0
                    && self.raw_data_size == 0
                    && self.memory_address != 0
                    && self.memory_data_size != 0
                    && self.attributes == 0;
            }

            TDX_METADATA_SECTION_TYPE_TEMP_MEM => {
                valid = self.data_offset == 0
                    && self.raw_data_size == 0
                    && self.memory_address != 0
                    && self.memory_data_size != 0
                    && self.attributes == 0;
            }

            TDX_METADATA_SECTION_TYPE_PAYLOAD => {
                valid = self.data_offset == 0
                    && self.raw_data_size == 0
                    && self.memory_address != 0
                    && self.memory_data_size != 0
                    && self.attributes == 0;
            }

            TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM => {
                valid = self.data_offset == 0
                    && self.raw_data_size == 0
                    && self.memory_address != 0
                    && self.memory_data_size != 0
                    && self.attributes == 0;
            }

            _ => {}
        }
        valid
    }
}

#[repr(C)]
#[derive(Pwrite, Pread)]
pub struct TdxMetadataGuid {
    pub guid: Guid,
}

impl TdxMetadataGuid {
    /// Check whether it's a valid
    pub fn is_valid(&self) -> bool {
        let metadata_guid = Guid::from_str(TDX_METADATA_GUID_STR).unwrap();
        metadata_guid == self.guid
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.guid.as_bytes()
    }

    /// Return TdxMetadataGuid based on the input buffer
    ///
    /// # Arguments
    ///
    /// * `buffer` - A buffer contains TdxMetadata guid.
    pub fn from_bytes(buffer: &[u8; 16]) -> Option<TdxMetadataGuid> {
        let guid = Guid::from_bytes(buffer);
        let metadata_guid = TdxMetadataGuid { guid: guid };
        if metadata_guid.is_valid() {
            Some(metadata_guid)
        } else {
            None
        }
    }
}

impl Default for TdxMetadataGuid {
    fn default() -> Self {
        TdxMetadataGuid {
            guid: Guid::from_str(TDX_METADATA_GUID_STR).unwrap(),
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
            payload_sections: [Default::default(); 2],
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
        let guid = TdxMetadataGuid::default();

        assert_eq!(guid.is_valid(), true);
    }
}

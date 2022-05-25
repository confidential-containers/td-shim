// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;

use alloc::string::String;
use core::{ptr::slice_from_raw_parts, str::FromStr};
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
#[derive(Debug, Pread, Pwrite)]
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
#[derive(Clone, Copy, Debug, Default, Pwrite, Pread)]
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

    /// check the validness of sections
    pub fn is_valid_sections(sections: &[TdxMetadataSection]) -> bool {
        let mut bfv_cnt = 0;
        let mut hob_cnt = 0;
        let mut perm_mem_cnt = 0;
        let mut payload_cnt = 0;
        let mut payload_param_cnt = 0;
        let check_data_memory_fields =
            |data_offset: u32, data_size: u32, memory_address: u64, memory_size: u64| -> bool {
                if data_size == 0 && data_offset != 0 {
                    return false;
                }
                if data_size != 0 && memory_size < data_size as u64 {
                    return false;
                }
                if (memory_address & 0xfff) != 0 {
                    return false;
                }
                true
            };
        for section in sections.iter() {
            match section.r#type {
                TDX_METADATA_SECTION_TYPE_BFV => {
                    // A TD-Shim shall include at least one BFV and the reset vector shall be inside
                    // of BFV. The RawDataSize of BFV must be non-zero.
                    bfv_cnt += 1;
                    if section.raw_data_size == 0 {
                        return false;
                    }
                    if section.attributes != TDX_METADATA_ATTRIBUTES_EXTENDMR {
                        return false;
                    }
                    if !check_data_memory_fields(
                        section.data_offset,
                        section.raw_data_size,
                        section.memory_address,
                        section.memory_data_size,
                    ) {
                        return false;
                    }
                }

                TDX_METADATA_SECTION_TYPE_CFV => {
                    // A TD-Shim may have zero, one or multiple CFVs. The RawDataSize of CFV must be
                    // non-zero.
                    if section.raw_data_size == 0 {
                        return false;
                    }
                    if section.attributes != 0 {
                        return false;
                    }
                    if !check_data_memory_fields(
                        section.data_offset,
                        section.raw_data_size,
                        section.memory_address,
                        section.memory_data_size,
                    ) {
                        return false;
                    }
                }

                TDX_METADATA_SECTION_TYPE_TD_HOB => {
                    // A TD-Shim may have zero or one TD_HOB section. The RawDataSize of TD_HOB must
                    // be zero. If TD-Shim reports zero TD_HOB section, then TD-Shim shall report
                    // all required memory in PermMem section.
                    hob_cnt += 1;
                    if hob_cnt > 1 {
                        return false;
                    }
                    if section.raw_data_size != 0 || section.data_offset != 0 {
                        return false;
                    }
                    if section.attributes != 0 {
                        return false;
                    }
                    if !check_data_memory_fields(
                        section.data_offset,
                        section.raw_data_size,
                        section.memory_address,
                        section.memory_data_size,
                    ) {
                        return false;
                    }
                }

                TDX_METADATA_SECTION_TYPE_TEMP_MEM => {
                    // The RawDataSize of TempMem must be zero.
                    if section.raw_data_size != 0 || section.data_offset != 0 {
                        return false;
                    }
                    if section.attributes != 0 {
                        return false;
                    }
                    if !check_data_memory_fields(
                        section.data_offset,
                        section.raw_data_size,
                        section.memory_address,
                        section.memory_data_size,
                    ) {
                        return false;
                    }
                }

                TDX_METADATA_SECTION_TYPE_PERM_MEM => {
                    // A TD-Shim may have zero, one or multiple PermMem section. The RawDataSize of
                    // PermMem must be zero. If a TD provides PermMem section, that means the TD
                    // will own the memory allocation. VMM shall allocate the permanent memory for
                    // this TD. TD will NOT use the system memory information in the TD HOB. Even if
                    // VMM adds system memory information in the TD HOB, it will ne ignored.
                    perm_mem_cnt += 1;
                    if section.raw_data_size != 0 || section.data_offset != 0 {
                        return false;
                    }
                    if section.attributes != 0 {
                        return false;
                    }
                    if !check_data_memory_fields(
                        section.data_offset,
                        section.raw_data_size,
                        section.memory_address,
                        section.memory_data_size,
                    ) {
                        return false;
                    }
                }

                TDX_METADATA_SECTION_TYPE_PAYLOAD => {
                    // A TD-Shim may have zero or one Payload. The RawDataSize of Payload must be
                    // non-zero, if the whole image includes the Payload. Otherwise the RawDataSize
                    // must be zero.
                    payload_cnt += 1;
                    if payload_cnt > 1 {
                        return false;
                    }
                    if section.attributes != 0 {
                        return false;
                    }
                    if !check_data_memory_fields(
                        section.data_offset,
                        section.raw_data_size,
                        section.memory_address,
                        section.memory_data_size,
                    ) {
                        return false;
                    }
                }

                TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM => {
                    // A TD-Shim may have zero or one PayloadParam. PayloadParam is present only if
                    // the Payload is present.
                    payload_param_cnt += 1;
                    if payload_param_cnt > 1 {
                        return false;
                    }
                    if section.attributes != 0 {
                        return false;
                    }
                    if !check_data_memory_fields(
                        section.data_offset,
                        section.raw_data_size,
                        section.memory_address,
                        section.memory_data_size,
                    ) {
                        return false;
                    }
                }

                _ => {
                    return false;
                }
            }
        }

        // A TD-Shim shall include at least one BFV
        if bfv_cnt == 0 {
            return false;
        }
        // If TD-Shim reports zero TD_HOB section, then TD-Shim shall report
        // all required memory in PermMem section.
        if hob_cnt == 0 && perm_mem_cnt == 0 {
            return false;
        }
        // PayloadParam is present only if the Payload is present.
        if payload_cnt == 0 && payload_param_cnt != 0 {
            return false;
        }
        true
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
        assert_eq!(size_of::<TdxMetadata>(), 288);
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

// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;

use alloc::string::String;
use core::{ptr::slice_from_raw_parts, str::FromStr};
use scroll::{Pread, Pwrite};
use td_uefi_pi::pi::guid::Guid;

/// TDX Metadata GUID defined in td-shim specification
pub const TDX_METADATA_GUID_STR: &str = "E9EAF9F3-168E-44D5-A8EB-7F4D8738F6AE";
pub const TDX_METADATA_GUID: Guid = Guid::from_fields(
    0xE9EAF9F3,
    0x168E,
    0x44D5,
    [0xA8, 0xEB, 0x7F, 0x4D, 0x87, 0x38, 0xF6, 0xAE],
);

/// 'TDVF' signature
pub const TDX_METADATA_SIGNATURE: u32 = 0x46564454;
/// Version of the `TdxMetadataDescriptor` structure. It must be 1.
pub const TDX_METADATA_VERSION: u32 = 1;
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
pub const TDX_METADATA_ATTRIBUTES_PAGE_AUG: u32 = 0x00000002;

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

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const TdxMetadataDescriptor as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
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

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const TdxMetadataSection as *const u8,
                core::mem::size_of::<Self>(),
            )
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

#[derive(Debug)]
pub enum TdxMetadataError {
    InvalidSection,
}

pub fn validate_sections(sections: &[TdxMetadataSection]) -> Result<(), TdxMetadataError> {
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
                if bfv_cnt == i32::MAX {
                    return Err(TdxMetadataError::InvalidSection);
                }
                bfv_cnt += 1;
                if section.raw_data_size == 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if section.attributes != TDX_METADATA_ATTRIBUTES_EXTENDMR {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if !check_data_memory_fields(
                    section.data_offset,
                    section.raw_data_size,
                    section.memory_address,
                    section.memory_data_size,
                ) {
                    return Err(TdxMetadataError::InvalidSection);
                }
            }

            TDX_METADATA_SECTION_TYPE_CFV => {
                // A TD-Shim may have zero, one or multiple CFVs. The RawDataSize of CFV must be
                // non-zero.
                if section.raw_data_size == 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if section.attributes != 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if !check_data_memory_fields(
                    section.data_offset,
                    section.raw_data_size,
                    section.memory_address,
                    section.memory_data_size,
                ) {
                    return Err(TdxMetadataError::InvalidSection);
                }
            }

            TDX_METADATA_SECTION_TYPE_TD_HOB => {
                // A TD-Shim may have zero or one TD_HOB section. The RawDataSize of TD_HOB must
                // be zero. If TD-Shim reports zero TD_HOB section, then TD-Shim shall report
                // all required memory in PermMem section.
                if hob_cnt == i32::MAX {
                    return Err(TdxMetadataError::InvalidSection);
                }
                hob_cnt += 1;
                if hob_cnt > 1 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if section.raw_data_size != 0 || section.data_offset != 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if section.attributes != 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if !check_data_memory_fields(
                    section.data_offset,
                    section.raw_data_size,
                    section.memory_address,
                    section.memory_data_size,
                ) {
                    return Err(TdxMetadataError::InvalidSection);
                }
            }

            TDX_METADATA_SECTION_TYPE_TEMP_MEM => {
                // The RawDataSize of TempMem must be zero.
                if section.raw_data_size != 0 || section.data_offset != 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if section.attributes != 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if !check_data_memory_fields(
                    section.data_offset,
                    section.raw_data_size,
                    section.memory_address,
                    section.memory_data_size,
                ) {
                    return Err(TdxMetadataError::InvalidSection);
                }
            }

            TDX_METADATA_SECTION_TYPE_PERM_MEM => {
                // A TD-Shim may have zero, one or multiple PermMem section. The RawDataSize of
                // PermMem must be zero. If a TD provides PermMem section, that means the TD
                // will own the memory allocation. VMM shall allocate the permanent memory for
                // this TD. TD will NOT use the system memory information in the TD HOB. Even if
                // VMM adds system memory information in the TD HOB, it will ne ignored.
                if perm_mem_cnt == i32::MAX {
                    return Err(TdxMetadataError::InvalidSection);
                }
                perm_mem_cnt += 1;
                if section.raw_data_size != 0 || section.data_offset != 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if section.attributes != TDX_METADATA_ATTRIBUTES_PAGE_AUG {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if !check_data_memory_fields(
                    section.data_offset,
                    section.raw_data_size,
                    section.memory_address,
                    section.memory_data_size,
                ) {
                    return Err(TdxMetadataError::InvalidSection);
                }
            }

            TDX_METADATA_SECTION_TYPE_PAYLOAD => {
                // A TD-Shim may have zero or one Payload. The RawDataSize of Payload must be
                // non-zero, if the whole image includes the Payload. Otherwise the RawDataSize
                // must be zero.
                if payload_cnt == i32::MAX {
                    return Err(TdxMetadataError::InvalidSection);
                }
                payload_cnt += 1;
                if payload_cnt > 1 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if section.attributes != 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if !check_data_memory_fields(
                    section.data_offset,
                    section.raw_data_size,
                    section.memory_address,
                    section.memory_data_size,
                ) {
                    return Err(TdxMetadataError::InvalidSection);
                }
            }

            TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM => {
                // A TD-Shim may have zero or one PayloadParam. PayloadParam is present only if
                // the Payload is present.
                if payload_param_cnt == i32::MAX {
                    return Err(TdxMetadataError::InvalidSection);
                }
                payload_param_cnt += 1;
                if payload_param_cnt > 1 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if section.attributes != 0 {
                    return Err(TdxMetadataError::InvalidSection);
                }
                if !check_data_memory_fields(
                    section.data_offset,
                    section.raw_data_size,
                    section.memory_address,
                    section.memory_data_size,
                ) {
                    return Err(TdxMetadataError::InvalidSection);
                }
            }

            _ => {
                return Err(TdxMetadataError::InvalidSection);
            }
        }
    }

    // A TD-Shim shall include at least one BFV
    if bfv_cnt == 0 {
        return Err(TdxMetadataError::InvalidSection);
    }
    // If TD-Shim reports zero TD_HOB section, then TD-Shim shall report
    // all required memory in PermMem section.
    if hob_cnt == 0 && perm_mem_cnt == 0 {
        return Err(TdxMetadataError::InvalidSection);
    }
    // PayloadParam is present only if the Payload is present.
    if payload_cnt == 0 && payload_param_cnt != 0 {
        return Err(TdxMetadataError::InvalidSection);
    }

    Ok(())
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
        let tdx_metadata_guid: [u8; 16] = [
            0xF3, 0xF9, 0xEA, 0xE9, 0x8e, 0x16, 0xD5, 0x44, 0xA8, 0xEB, 0x7F, 0x4D, 0x87, 0x38,
            0xF6, 0xAE,
        ];
        let invalid_tdx_metadata_guid: [u8; 16] = [
            0xE9, 0xEA, 0xF9, 0xF3, 0x16, 0x8e, 0x44, 0xD5, 0xA8, 0xEB, 0x7F, 0x4D, 0x87, 0x38,
            0xF6, 0xAE,
        ];
        let guid = TdxMetadataGuid::default();

        assert_eq!(&tdx_metadata_guid, guid.as_bytes());
        assert_eq!(&tdx_metadata_guid, TDX_METADATA_GUID.as_bytes());
        assert_eq!(guid.is_valid(), true);

        let guid_pread: TdxMetadataGuid = tdx_metadata_guid.pread(0).unwrap();
        assert_eq!(guid_pread.as_bytes(), guid.as_bytes());

        let guid = TdxMetadataGuid::from_bytes(&tdx_metadata_guid).unwrap();
        assert_eq!(guid.as_bytes(), &tdx_metadata_guid);

        assert!(TdxMetadataGuid::from_bytes(&invalid_tdx_metadata_guid).is_none());
    }

    #[test]
    fn test_tdx_metadata_section() {
        assert_eq!(TdxMetadataSection::get_type_name(0).unwrap(), "BFV");
        assert_eq!(TdxMetadataSection::get_type_name(1).unwrap(), "CFV");
        assert_eq!(TdxMetadataSection::get_type_name(2).unwrap(), "TD_HOB");
        assert_eq!(TdxMetadataSection::get_type_name(3).unwrap(), "TempMem");
        assert_eq!(TdxMetadataSection::get_type_name(4).unwrap(), "PermMem");
        assert_eq!(TdxMetadataSection::get_type_name(5).unwrap(), "Payload");
        assert_eq!(
            TdxMetadataSection::get_type_name(6).unwrap(),
            "PayloadParam"
        );

        assert!(TdxMetadataSection::get_type_name(7).is_none())
    }

    #[test]
    fn test_validate_sections() {
        // empty sections at leaset one bfv section
        let sections = [];
        assert!(!validate_sections(&sections).is_ok());

        // init sections include all types
        let mut sections: [TdxMetadataSection; 6] = [TdxMetadataSection::default(); 6];
        // BFV
        sections[0] = TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0xf7e000,
            memory_address: 0xff082000,
            memory_data_size: 0xf7e000,
            attributes: 1,
            r#type: TDX_METADATA_SECTION_TYPE_BFV,
        };
        // CFV
        sections[1] = TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0x40000,
            memory_address: 0xff000000,
            memory_data_size: 0x40000,
            attributes: 0,
            r#type: TDX_METADATA_SECTION_TYPE_CFV,
        };
        // TD HOB
        sections[2] = TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: 0x820000,
            memory_data_size: 0x20000,
            attributes: 0,
            r#type: TDX_METADATA_SECTION_TYPE_TD_HOB,
        };
        // Temp memory
        sections[3] = TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: 0xFF040000,
            memory_data_size: 0x1000,
            attributes: 0,
            r#type: TDX_METADATA_SECTION_TYPE_TEMP_MEM,
        };
        // Payload
        sections[4] = TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: 0x1200000,
            memory_data_size: 0x8000000,
            attributes: 0,
            r#type: TDX_METADATA_SECTION_TYPE_PAYLOAD,
        };
        // PayloadParam
        sections[5] = TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: 0x1100000,
            memory_data_size: 0x100000,
            attributes: 0,
            r#type: TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM,
        };

        assert!(validate_sections(&sections).is_ok());

        // test BFV
        // section.raw_data_size == 0
        sections[0].raw_data_size = 0;
        assert!(!validate_sections(&sections).is_ok());
        sections[0].raw_data_size = 0xf7e000;
        // section.attributes != TDX_METADATA_ATTRIBUTES_EXTENDMR
        sections[0].attributes = 0;
        assert!(!validate_sections(&sections).is_ok());
        sections[0].attributes = TDX_METADATA_ATTRIBUTES_EXTENDMR;
        // memory_data_size < raw_data_size
        sections[0].memory_data_size = sections[0].raw_data_size as u64 - 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[0].memory_data_size += 1;
        // memory_address is not 4K align
        sections[0].memory_address += 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[0].memory_address -= 1;
        // multiple CFV
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_BFV;
        sections[3].attributes = TDX_METADATA_ATTRIBUTES_EXTENDMR;
        sections[3].raw_data_size = sections[3].memory_data_size as u32;
        assert!(validate_sections(&sections).is_ok());
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
        sections[3].attributes = 0;
        sections[3].raw_data_size = 0;

        // test CFV
        // no CFV
        sections[1].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
        sections[1].raw_data_size = 0;
        assert!(validate_sections(&sections).is_ok());
        sections[1].r#type = TDX_METADATA_SECTION_TYPE_CFV;
        // section.raw_data_size == 0
        assert!(!validate_sections(&sections).is_ok());
        sections[1].raw_data_size = 0x40000;
        // section.attributes != 0
        sections[1].attributes = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[1].attributes = 0;
        // memory_data_size < raw_data_size
        sections[1].memory_data_size = sections[1].raw_data_size as u64 - 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[1].memory_data_size += 1;
        // memory_address is not 4K align
        sections[1].memory_address += 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[1].memory_address -= 1;
        // multiple CFV
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_CFV;
        sections[3].raw_data_size = sections[3].memory_data_size as u32;
        assert!(validate_sections(&sections).is_ok());
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
        sections[3].raw_data_size = 0;

        // test TD HOB
        // no TD HOB and no PermMem
        sections[2].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].r#type = TDX_METADATA_SECTION_TYPE_TD_HOB;
        // raw_data_size != 0
        sections[2].raw_data_size = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].raw_data_size = 0;
        // data_offset != 0
        sections[2].data_offset = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].data_offset = 0;
        // section.attributes != 0
        sections[2].attributes = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].attributes = 0;
        // memory_address is not 4K align
        sections[2].memory_address += 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].memory_address -= 1;
        // multiple TD HOB
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_TD_HOB;
        assert!(!validate_sections(&sections).is_ok());
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;

        // test TEMP MEM
        // no TEMP MEM already covered by upon test case

        // raw_data_size != 0
        sections[3].raw_data_size = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[3].raw_data_size = 0;
        // data_offset != 0
        sections[3].data_offset = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[3].data_offset = 0;
        // section.attributes != 0
        sections[3].attributes = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[3].attributes = 0;
        // memory_address is not 4K align
        sections[3].memory_address += 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[3].memory_address -= 1;
        // multiple TEMP MEM already covered by CFV test

        // test PERM MEM
        // no TD HOB  one PERM MEM
        sections[2].r#type = TDX_METADATA_SECTION_TYPE_PERM_MEM;
        sections[2].attributes = TDX_METADATA_ATTRIBUTES_PAGE_AUG;
        assert!(validate_sections(&sections).is_ok());
        // raw_data_size != 0
        sections[2].raw_data_size = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].raw_data_size = 0;
        // data_offset != 0
        sections[2].data_offset = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].data_offset = 0;
        // section.attributes != 2
        sections[2].attributes = 0;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].attributes = TDX_METADATA_ATTRIBUTES_EXTENDMR;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].attributes = TDX_METADATA_ATTRIBUTES_PAGE_AUG;
        // memory_address is not 4K align
        sections[2].memory_address += 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[2].memory_address -= 1;
        // both have TD HOB and PERM MEM
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_TD_HOB;
        assert!(validate_sections(&sections).is_ok());
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
        // multiple PERM MEM
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_PERM_MEM;
        sections[3].attributes = TDX_METADATA_ATTRIBUTES_PAGE_AUG;
        assert!(validate_sections(&sections).is_ok());
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
        sections[3].attributes = 0;

        // test PAYLAOD
        // no PAYLOAD but has PAYLOAD_PARAM
        sections[4].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
        assert!(!validate_sections(&sections).is_ok());
        // no PAYLOAD and PAYLOAD_PARAM
        sections[5].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
        assert!(validate_sections(&sections).is_ok());
        sections[4].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD;
        sections[5].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM;
        // section.attributes != 0
        sections[4].attributes = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[4].attributes = 0;
        // raw_data_size == 0 but data_offset != 0
        sections[4].data_offset = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[4].data_offset = 0;
        // memory_address is not 4K align
        sections[4].memory_address += 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[4].memory_address -= 1;
        // multiple PAYLOAD
        sections[5].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD;
        assert!(!validate_sections(&sections).is_ok());
        sections[5].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM;

        // test PAYLOAD_PARAM
        sections[5].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
        assert!(validate_sections(&sections).is_ok());
        sections[5].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM;
        // section.attributes != 0
        sections[5].attributes = 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[5].attributes = 0;
        // memory_address is not 4K align
        sections[5].memory_address += 1;
        assert!(!validate_sections(&sections).is_ok());
        sections[5].memory_address -= 1;
        // multiple PAYLOAD_PARAM
        sections[3].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM;
        assert!(!validate_sections(&sections).is_ok());

        // Invalid seciton type
        sections[5].r#type = TDX_METADATA_SECTION_TYPE_MAX;
        assert!(!validate_sections(&sections).is_ok());
    }

    #[test]
    fn test_tdxmetadataptr() {
        let ptr = TdxMetadataPtr { ptr: 0x1000 };

        assert_eq!(ptr.as_bytes(), 0x1000_i32.to_le_bytes())
    }
}

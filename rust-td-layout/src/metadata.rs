// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use scroll::{Pread, Pwrite};

pub const TDX_METADATA_GUID1: u32 = 0xe9eaf9f3;
pub const TDX_METADATA_GUID2: u32 = 0x44d5168e;
pub const TDX_METADATA_GUID3: u32 = 0x4d7feba8;
pub const TDX_METADATA_GUID4: u32 = 0xaef63887;

pub const TDX_METADATA_SIGNATURE: u32 = 0x46564454;

pub const TDX_METADATA_SECTION_TYPE_BFV: u32 = 0;
pub const TDX_METADATA_SECTION_TYPE_CFV: u32 = 1;
pub const TDX_METADATA_SECTION_TYPE_TD_HOB: u32 = 2;
pub const TDX_METADATA_SECTION_TYPE_TEMP_MEM: u32 = 3;
pub const TDX_METADATA_SECTION_TYPE_PAYLOAD: u32 = 5;
pub const TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM: u32 = 6;

pub const TDX_METADATA_ATTRIBUTES_EXTENDMR: u32 = 0x00000001;

#[repr(C)]
#[derive(Default, Pread, Pwrite)]
pub struct TdxMetadataDescriptor {
    pub signature: u32,
    pub length: u32,
    pub version: u32,
    pub number_of_section_entry: u32,
}

#[repr(C)]
#[derive(Default, Pwrite, Pread)]
pub struct TdxMetadataSection {
    pub data_offset: u32,
    pub raw_data_size: u32,
    pub memory_address: u64,
    pub memory_data_size: u64,
    pub r#type: u32,
    pub attributes: u32,
}

#[repr(C)]
#[derive(Default, Pwrite, Pread)]
pub struct TdxMetadataGuid {
    pub data1: u32,
    pub data2: u32,
    pub data3: u32,
    pub data4: u32,
}

#[repr(C)]
#[derive(Default, Pwrite)]
pub struct TdxMetadata {
    pub guid: TdxMetadataGuid,
    pub descriptor: TdxMetadataDescriptor,
    pub sections: [TdxMetadataSection; 6],
    #[cfg(feature = "boot-kernel")]
    pub payload_sections: [TdxMetadataSection; 2],
}

#[repr(C)]
#[derive(Default, Pwrite, Pread)]
pub struct TdxMetadataPtr {
    pub ptr: u32,
}

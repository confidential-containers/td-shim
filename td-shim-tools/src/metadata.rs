// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use serde::de::Error;
use serde::{de, Deserialize};
use std::{mem::size_of, vec::Vec};
use td_layout::build_time::*;
use td_layout::runtime::*;
use td_shim_interface::metadata::{
    TdxMetadataDescriptor, TDX_METADATA_GUID, TDX_METADATA_SECTION_TYPE_BFV,
    TDX_METADATA_SECTION_TYPE_CFV, TDX_METADATA_SECTION_TYPE_PAYLOAD,
    TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM, TDX_METADATA_SECTION_TYPE_PERM_MEM,
    TDX_METADATA_SECTION_TYPE_TD_HOB, TDX_METADATA_SECTION_TYPE_TD_INFO,
    TDX_METADATA_SECTION_TYPE_TEMP_MEM, TDX_METADATA_SIGNATURE, TDX_METADATA_VERSION,
};
use td_shim_interface::td_uefi_pi::pi::guid::Guid;

use crate::linker::PayloadType;

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct TdxMetadataSection {
    #[serde(rename = "DataOffset", deserialize_with = "u32_deserialize")]
    pub data_offset: u32,
    #[serde(rename = "RawDataSize", deserialize_with = "u32_deserialize")]
    pub raw_data_size: u32,
    #[serde(rename = "MemoryAddress", deserialize_with = "u64_deserialize")]
    pub memory_address: u64,
    #[serde(rename = "MemoryDataSize", deserialize_with = "u64_deserialize")]
    pub memory_data_size: u64,
    #[serde(rename = "Type", deserialize_with = "type_deserialize")]
    pub r#type: u32,
    #[serde(rename = "Attributes", deserialize_with = "u32_deserialize")]
    pub attributes: u32,
}

impl TdxMetadataSection {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const TdxMetadataSection as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

fn u32_deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    parse_int::parse::<u32>(s).map_err(D::Error::custom)
}

fn u64_deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    parse_int::parse::<u64>(s).map_err(D::Error::custom)
}

fn type_deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    match s {
        "BFV" => Ok(TDX_METADATA_SECTION_TYPE_BFV),
        "CFV" => Ok(TDX_METADATA_SECTION_TYPE_CFV),
        "TD_HOB" => Ok(TDX_METADATA_SECTION_TYPE_TD_HOB),
        "TempMem" => Ok(TDX_METADATA_SECTION_TYPE_TEMP_MEM),
        "PermMem" => Ok(TDX_METADATA_SECTION_TYPE_PERM_MEM),
        "Payload" => Ok(TDX_METADATA_SECTION_TYPE_PAYLOAD),
        "PayloadParam" => Ok(TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM),
        "TdInfo" => Ok(TDX_METADATA_SECTION_TYPE_TD_INFO),
        _ => Err(D::Error::custom("Invalid metadata section type")),
    }
}

#[derive(Debug, Deserialize)]
pub struct MetadataSections {
    #[serde(rename = "Sections")]
    inner: Vec<TdxMetadataSection>,
}

impl MetadataSections {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    pub fn as_slice(&self) -> &[TdxMetadataSection] {
        self.inner.as_slice()
    }

    pub fn add(&mut self, section: TdxMetadataSection) {
        self.inner.push(section)
    }
}

fn basic_metadata_sections(payload_type: PayloadType) -> MetadataSections {
    use td_shim_interface::metadata::TDX_METADATA_ATTRIBUTES_EXTENDMR;

    let mut metadata_sections = MetadataSections::new();

    // BFV
    let bfv_offset =
        if cfg!(any(feature = "exec-payload-section")) || payload_type == PayloadType::Linux {
            TD_SHIM_METADATA_OFFSET
        } else {
            TD_SHIM_PAYLOAD_OFFSET
        };

    let bfv_data_size =
        if cfg!(any(feature = "exec-payload-section")) || payload_type == PayloadType::Linux {
            (TD_SHIM_METADATA_SIZE + TD_SHIM_IPL_SIZE + TD_SHIM_RESET_VECTOR_SIZE) as u64
        } else {
            (TD_SHIM_PAYLOAD_SIZE
                + TD_SHIM_METADATA_SIZE
                + TD_SHIM_IPL_SIZE
                + TD_SHIM_RESET_VECTOR_SIZE) as u64
        };

    let bfv_memory_address =
        if cfg!(any(feature = "exec-payload-section")) || payload_type == PayloadType::Linux {
            TD_SHIM_METADATA_BASE
        } else {
            TD_SHIM_PAYLOAD_BASE
        };

    metadata_sections.add(TdxMetadataSection {
        data_offset: bfv_offset,
        raw_data_size: bfv_data_size as u32,
        memory_address: bfv_memory_address as u64,
        memory_data_size: bfv_data_size,
        r#type: TDX_METADATA_SECTION_TYPE_BFV,
        attributes: TDX_METADATA_ATTRIBUTES_EXTENDMR,
    });

    // CFV
    metadata_sections.add(TdxMetadataSection {
        data_offset: TD_SHIM_CONFIG_OFFSET,
        raw_data_size: TD_SHIM_CONFIG_SIZE,
        memory_address: TD_SHIM_CONFIG_BASE as u64,
        memory_data_size: TD_SHIM_CONFIG_SIZE as u64,
        r#type: TDX_METADATA_SECTION_TYPE_CFV,
        attributes: 0,
    });

    // stack
    metadata_sections.add(TdxMetadataSection {
        data_offset: 0,
        raw_data_size: 0,
        memory_address: TD_SHIM_TEMP_STACK_BASE as u64,
        memory_data_size: TD_SHIM_TEMP_STACK_SIZE as u64,
        r#type: TDX_METADATA_SECTION_TYPE_TEMP_MEM,
        attributes: 0,
    });

    // heap
    metadata_sections.add(TdxMetadataSection {
        data_offset: 0,
        raw_data_size: 0,
        memory_address: TD_SHIM_TEMP_HEAP_BASE as u64,
        memory_data_size: TD_SHIM_TEMP_HEAP_SIZE as u64,
        r#type: TDX_METADATA_SECTION_TYPE_TEMP_MEM,
        attributes: 0,
    });

    // MAILBOX
    metadata_sections.add(TdxMetadataSection {
        data_offset: 0,
        raw_data_size: 0,
        memory_address: TD_SHIM_MAILBOX_BASE as u64,
        memory_data_size: TD_SHIM_MAILBOX_SIZE as u64,
        r#type: TDX_METADATA_SECTION_TYPE_TEMP_MEM,
        attributes: 0,
    });

    metadata_sections
}

pub fn default_metadata_sections(payload_type: PayloadType) -> MetadataSections {
    let mut metadata_sections = basic_metadata_sections(payload_type);

    if payload_type == PayloadType::Linux {
        // TD_HOB
        metadata_sections.add(TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: linux::TD_HOB_BASE as u64,
            memory_data_size: linux::TD_HOB_SIZE as u64,
            r#type: TDX_METADATA_SECTION_TYPE_TD_HOB,
            attributes: 0,
        });

        // kernel image
        metadata_sections.add(TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: linux::PAYLOAD_BASE as u64,
            memory_data_size: linux::PAYLOAD_SIZE as u64,
            r#type: TDX_METADATA_SECTION_TYPE_PAYLOAD,
            attributes: 0,
        });

        // kernel parameters
        metadata_sections.add(TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: linux::PAYLOAD_PARAMETER_BASE as u64,
            memory_data_size: linux::PAYLOAD_PARAMETER_SIZE as u64,
            r#type: TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM,
            attributes: 0,
        });
    } else {
        // TD_HOB
        metadata_sections.add(TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: exec::TD_HOB_BASE as u64,
            memory_data_size: exec::TD_HOB_SIZE as u64,
            r#type: TDX_METADATA_SECTION_TYPE_TD_HOB,
            attributes: 0,
        });

        if cfg!(feature = "exec-payload-section") {
            println!("default_metadata_sections_exec_payload");
            // payload image
            metadata_sections.add(TdxMetadataSection {
                data_offset: TD_SHIM_PAYLOAD_OFFSET,
                raw_data_size: TD_SHIM_PAYLOAD_SIZE,
                memory_address: TD_SHIM_PAYLOAD_BASE as u64,
                memory_data_size: TD_SHIM_PAYLOAD_SIZE as u64,
                r#type: TDX_METADATA_SECTION_TYPE_PAYLOAD,
                attributes: 0,
            });
        }
    }

    metadata_sections
}

#[repr(C)]
pub struct TdxMetadata {
    pub guid: Guid,
    pub descriptor: TdxMetadataDescriptor,
    /// Sections for BFV, CFV, stack, heap, TD_HOP, Mailbox.
    pub sections: MetadataSections,
}

impl TdxMetadata {
    pub fn new(sections: MetadataSections) -> Option<Self> {
        let length = size_of::<TdxMetadataDescriptor>()
            + sections.as_slice().len() * size_of::<TdxMetadataSection>();
        if length > u32::MAX as usize {
            return None;
        }
        Some(TdxMetadata {
            guid: TDX_METADATA_GUID,
            descriptor: TdxMetadataDescriptor {
                signature: TDX_METADATA_SIGNATURE,
                length: length as u32,
                version: TDX_METADATA_VERSION,
                number_of_section_entry: sections.as_slice().len() as u32,
            },
            sections,
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut metadata = Vec::new();
        metadata.extend_from_slice(self.guid.as_bytes());
        metadata.extend_from_slice(self.descriptor.as_bytes());

        for section in self.sections.as_slice() {
            metadata.extend_from_slice(section.as_bytes());
        }

        metadata
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const EXAMPLE_SECTIONS: &str = "{
        \"Sections\": [
            {
                \"DataOffset\": \"0\",
                \"RawDataSize\": \"0x40000\",
                \"MemoryAddress\": \"0xFF000000\",
                \"MemoryDataSize\": \"0x40000\",
                \"Type\": \"CFV\",
                \"Attributes\": \"0x0\"
            },
            {
                \"DataOffset\": \"0x0\",
                \"RawDataSize\": \"0x0\",
                \"MemoryAddress\": \"0xFF042000\",
                \"MemoryDataSize\": \"0x20000\",
                \"Type\": \"TempMem\",
                \"Attributes\": \"0x0\"
            }
        ]
    }";

    const EXAMPLE_SECTIONS_INVALID: &str = "{
        \"Sections\": [
            {
                \"DataOffset\": \"0\",
                \"RawDataSize\": \"0x40000\",
                \"MemoryAddress\": \"0xFF000000\",
                \"MemoryDataSize\": \"0x40000\",
                \"Type\": \"1\",
                \"Attributes\": \"0x0\"
            }
        ]
    }";

    #[test]
    fn test_deserialize_metadata() {
        let btyes = EXAMPLE_SECTIONS.as_bytes();
        let metadata_json = serde_json::from_slice::<MetadataSections>(btyes).unwrap();

        let mut metadata_sections = MetadataSections::new();

        metadata_sections.add(TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0x40000,
            memory_address: 0xFF000000,
            memory_data_size: 0x40000,
            r#type: 1,
            attributes: 0,
        });
        metadata_sections.add(TdxMetadataSection {
            data_offset: 0,
            raw_data_size: 0,
            memory_address: 0xFF042000,
            memory_data_size: 0x20000,
            r#type: 3,
            attributes: 0,
        });

        assert_eq!(metadata_sections.as_slice(), metadata_json.as_slice())
    }

    #[test]
    fn test_deserialize_invalid_metadata() {
        let btyes = EXAMPLE_SECTIONS_INVALID.as_bytes();
        assert!(serde_json::from_slice::<MetadataSections>(btyes).is_err());
    }
}

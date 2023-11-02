// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use core::mem::size_of;
use core::str::FromStr;
use log::error;
use scroll::{Pread, Pwrite};
use td_layout::build_time::{TD_SHIM_FIRMWARE_BASE, TD_SHIM_FIRMWARE_SIZE};
use td_layout::memslice;
use td_shim::metadata::*;
use td_shim::speculation_barrier;
use td_shim::{
    PayloadInfo, TdPayloadInfoHobType, TD_ACPI_TABLE_HOB_GUID, TD_PAYLOAD_INFO_HOB_GUID,
};
use td_uefi_pi::pi::guid::Guid;
use td_uefi_pi::pi::hob::*;
use td_uefi_pi::{fv, hob, pi};

pub struct BootTimeStatic {
    sections: Vec<TdxMetadataSection>,

    // If metadata contains one/more `PermMem` sections,
    // TD-Shim should ignore the memory information in TD HOB.
    metadata_has_perm: bool,

    // If metadata contains `Payload` section and the attribute
    // is `1` (PAGE.AUG), the payload is not extended into MRTD and will
    // be measured into RTMR[1]
    payload_extend_rtmr: bool,
}

impl BootTimeStatic {
    // Validate the metadata and get the basic infomation from
    // it if any
    pub fn new() -> Option<Self> {
        let metadata_offset = unsafe { *((u32::MAX - TDX_METADATA_OFFSET + 1) as *const u32) };
        if metadata_offset >= TD_SHIM_FIRMWARE_SIZE
            || metadata_offset < size_of::<Guid>() as u32
            || metadata_offset > TD_SHIM_FIRMWARE_SIZE - size_of::<TdxMetadataDescriptor>() as u32
        {
            error!("Invalid TDX Metadata offset\n");
            return None;
        }

        let firmware = unsafe {
            core::slice::from_raw_parts(
                TD_SHIM_FIRMWARE_BASE as *const u8,
                TD_SHIM_FIRMWARE_SIZE as usize,
            )
        };

        // Validate TDX Metadata GUID
        let offset = metadata_offset as usize - size_of::<Guid>();
        let guid = &firmware[offset..offset + size_of::<Guid>()];
        if guid != TDX_METADATA_GUID.as_bytes() {
            error!("Invalid TDX Metadata GUID\n");
            return None;
        }

        // Then the descriptor
        let offset = metadata_offset as usize;
        let descriptor = firmware.pread::<TdxMetadataDescriptor>(offset).ok()?;
        if !descriptor.is_valid() {
            error!("Invalid TDX Metadata Descriptor: {:?}\n", descriptor);
            return None;
        }

        // check if the metadata length exceeds the firmware size
        let offset = metadata_offset + TDX_METADATA_DESCRIPTOR_LEN;
        let len = descriptor
            .number_of_section_entry
            .checked_mul(TDX_METADATA_SECTION_LEN)?;
        if offset.checked_add(len)? > TD_SHIM_FIRMWARE_SIZE {
            error!("Invalid TdxMetadata length\n");
            return None;
        }

        // Extract the sections one by one
        let mut offset = metadata_offset + TDX_METADATA_DESCRIPTOR_LEN;
        let mut sections = Vec::new();
        let mut metadata_has_perm = false;
        let mut payload_extend_rtmr = false;

        for _ in 0..descriptor.number_of_section_entry {
            let section = firmware.pread::<TdxMetadataSection>(offset as usize).ok()?;
            if section.r#type == TDX_METADATA_SECTION_TYPE_PERM_MEM {
                metadata_has_perm = true;
            }
            if section.r#type == TDX_METADATA_SECTION_TYPE_PAYLOAD && section.attributes == 0 {
                payload_extend_rtmr = true;
            }

            sections.push(section);
            offset += TDX_METADATA_SECTION_LEN;
        }

        // check the validness of the sections
        if validate_sections(&sections).is_err() {
            error!("Invalid metadata sections.\n");
            return None;
        }

        Some(Self {
            sections,
            metadata_has_perm,
            payload_extend_rtmr,
        })
    }

    pub fn sections(&self) -> &[TdxMetadataSection] {
        self.sections.as_slice()
    }

    pub fn payload_extend_rtmr(&self) -> bool {
        self.payload_extend_rtmr
    }
}

pub struct BootTimeDynamic<'a> {
    // If metadata contains the `TD_HOB` section, TD-Shim
    // can get additional information from TD HOB
    td_hob: Option<&'static [u8]>,

    pub memory: Vec<ResourceDescription>,
    pub acpi_tables: Vec<&'a [u8]>,
    pub payload_info: Option<PayloadInfo>,
    pub payload_param: Option<&'a [u8]>,
}

impl<'a> BootTimeDynamic<'a> {
    pub fn new(static_info: &BootTimeStatic) -> Option<Self> {
        let mut td_hob = static_info
            .sections()
            .iter()
            .find(|&section| section.r#type == TDX_METADATA_SECTION_TYPE_TD_HOB)
            .and_then(|section| unsafe {
                Some(core::slice::from_raw_parts(
                    section.memory_address as *const u8,
                    section.memory_data_size as usize,
                ))
            });

        if let Some(td_hob) = td_hob {
            // If we cannot validate or get correct information from TD HOB,
            // return None.
            let mut dynamic_info = Self::parse_td_hob(td_hob)?;

            // If `PermMem` exist in metadata, use the static memory information in
            // the metadata
            if static_info.metadata_has_perm {
                dynamic_info.memory = Self::parse_metadata(static_info.sections());
            }

            Some(dynamic_info)
        } else if static_info.metadata_has_perm {
            // If `TD_HOB` section does not exist but `PermMem` exists, use static
            // memory information in the metadata
            Some(Self {
                td_hob: None,
                memory: Self::parse_metadata(static_info.sections()),
                payload_info: None,
                payload_param: None,
                acpi_tables: Vec::new(),
            })
        } else {
            log::info!("both not exists\n");
            // If there is no `PermMem` or `TD_HOB` section in metadata, retur None
            None
        }
    }

    pub fn td_hob(&self) -> Option<&'static [u8]> {
        self.td_hob
    }

    fn parse_td_hob(td_hob: &'static [u8]) -> Option<Self> {
        let mut memory = Vec::new();
        let mut acpi_tables = Vec::new();
        let mut payload_info = None;
        let mut payload_param = None;

        let hob_list = hob::check_hob_integrity(td_hob)?;
        hob::dump_hob(hob_list);

        let mut offset = 0;
        loop {
            let hob = &hob_list[offset..];
            let header: Header = hob.pread(0).ok()?;
            match header.r#type {
                HOB_TYPE_RESOURCE_DESCRIPTOR => {
                    let resource_hob = hob.pread::<ResourceDescription>(0).ok()?;
                    if resource_hob.resource_type == RESOURCE_SYSTEM_MEMORY
                        || resource_hob.resource_type == RESOURCE_MEMORY_RESERVED
                        || resource_hob.resource_type == RESOURCE_MEMORY_UNACCEPTED
                    {
                        memory.push(resource_hob)
                    }
                }
                HOB_TYPE_GUID_EXTENSION => {
                    let guided_hob: GuidExtension = hob.pread(0).ok()?;
                    let hob_data = hob::get_guid_data(hob)?;
                    if &guided_hob.name == TD_PAYLOAD_INFO_HOB_GUID.as_bytes() {
                        payload_info = Some(hob_data.pread::<PayloadInfo>(0).ok()?);
                    } else if &guided_hob.name == TD_ACPI_TABLE_HOB_GUID.as_bytes() {
                        acpi_tables.push(hob_data);
                    }
                }
                HOB_TYPE_END_OF_HOB_LIST => {
                    break;
                }
                HOB_TYPE_HANDOFF => {}
                _ => {
                    return None;
                }
            }
            offset = hob::align_to_next_hob_offset(hob_list.len(), offset, header.length)?;
        }

        Some(Self {
            td_hob: Some(hob_list),
            memory,
            payload_info,
            payload_param,
            acpi_tables,
        })
    }

    fn parse_metadata(sections: &[TdxMetadataSection]) -> Vec<ResourceDescription> {
        let mut memory = Vec::new();
        for section in sections {
            let resource_type = if section.r#type == TDX_METADATA_SECTION_TYPE_PERM_MEM {
                RESOURCE_MEMORY_UNACCEPTED
            } else {
                RESOURCE_SYSTEM_MEMORY
            };

            let resource = ResourceDescription {
                header: Header {
                    r#type: HOB_TYPE_RESOURCE_DESCRIPTOR,
                    length: size_of::<ResourceDescription>() as u16,
                    reserved: 0,
                },
                owner: [0u8; 16],
                resource_type,
                resource_attribute: 0,
                physical_start: section.memory_address,
                resource_length: section.memory_data_size,
            };

            memory.push(resource)
        }

        memory
    }
}

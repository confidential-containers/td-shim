// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use alloc::vec::Vec;
use core::mem::size_of;
use scroll::{Pread, Pwrite};
use td_shim::speculation_barrier;
use td_shim::{PayloadInfo, TdKernelInfoHobType, TD_ACPI_TABLE_HOB_GUID, TD_KERNEL_INFO_HOB_GUID};
use td_uefi_pi::pi::hob::*;
use td_uefi_pi::{fv, hob, pi};

pub struct TdHobInfo<'a> {
    pub memory: Vec<ResourceDescription>,
    pub acpi_tables: Vec<&'a [u8]>,
    pub payload_info: Option<PayloadInfo>,
    pub payload_param: Option<&'a [u8]>,
}

impl<'a> TdHobInfo<'a> {
    /// Check the integrity of HOB list and return the HOB slice with real HOB length
    pub fn check_hob_integrity(hob_list: &[u8]) -> Option<&[u8]> {
        let mut offset = 0;
        let hob_length = hob::get_hob_total_size(hob_list)?;
        if hob_length > hob_list.len() {
            return None;
        }

        loop {
            let hob = &hob_list[offset..];
            let header: Header = hob.pread(0).ok()?;

            // A valid HOB should has non-zero length and zero reserved field,
            if header.length == 0 || header.length as usize > hob.len() || header.reserved != 0 {
                return None;
            }

            match header.r#type {
                HOB_TYPE_HANDOFF => {
                    if header.length as usize != size_of::<HandoffInfoTable>() {
                        return None;
                    }
                    let phit_hob: HandoffInfoTable = hob.pread(0).ok()?;

                    // This address must be 4-KB aligned to meet page restrictions
                    if phit_hob.efi_memory_top % 0x1000 != 0 {
                        log::info!(
                            "PHIT HOB does not hold a 4-KB aligned EFI memory top address: {:x}\n",
                            phit_hob.efi_memory_top
                        );
                        return None;
                    }
                }
                HOB_TYPE_END_OF_HOB_LIST => return Some(&hob_list[..hob_length]),
                HOB_TYPE_RESOURCE_DESCRIPTOR => {
                    if header.length as usize != size_of::<ResourceDescription>() {
                        return None;
                    }
                    let resource_hob: ResourceDescription = hob.pread(0).ok()?;
                    if resource_hob.resource_type >= RESOURCE_MAX_MEMORY_TYPE
                        || resource_hob.resource_attribute & (!RESOURCE_ATTRIBUTE_ALL) != 0
                    {
                        log::info!("Invalid resource type or attributes:\n");
                        resource_hob.dump();
                        return None;
                    }
                }
                HOB_TYPE_MEMORY_ALLOCATION => {
                    if header.length as usize != size_of::<MemoryAllocation>() {
                        return None;
                    }
                }
                HOB_TYPE_FV => {
                    if header.length as usize != size_of::<FirmwareVolume>() {
                        return None;
                    }
                }
                HOB_TYPE_FV2 => {
                    if header.length as usize != size_of::<FirmwareVolume2>() {
                        return None;
                    }
                }
                HOB_TYPE_FV3 => {
                    if header.length as usize != size_of::<FirmwareVolume3>() {
                        return None;
                    }
                }
                HOB_TYPE_CPU => {
                    if header.length as usize != size_of::<Cpu>() {
                        return None;
                    }

                    let cpu_hob: Cpu = hob.pread(0).ok()?;
                    // Reserved field is expected to be zero
                    if &cpu_hob.reserved != &[0u8; 6] {
                        return None;
                    }
                }
                HOB_TYPE_GUID_EXTENSION => {
                    // GUID Extension HOB has variable length
                }
                // Unsupported types
                _ => return None,
            }
            offset = hob::align_to_next_hob_offset(hob_length, offset, header.length)?;
        }
    }

    pub fn read_from_hob(raw: &'a [u8]) -> Option<Self> {
        let mut offset = 0;
        let mut payload_info = None;
        let mut payload_param = None;
        let mut acpi_tables: Vec<&[u8]> = Vec::new();
        let mut memory: Vec<ResourceDescription> = Vec::new();

        loop {
            let hob = &raw[offset..];
            let header: Header = hob.pread(0).ok()?;
            match header.r#type {
                HOB_TYPE_RESOURCE_DESCRIPTOR => {
                    let resource_hob = hob.pread::<ResourceDescription>(0).ok()?;
                    if resource_hob.resource_type == RESOURCE_SYSTEM_MEMORY
                        || resource_hob.resource_type == RESOURCE_MEMORY_RESERVED
                    {
                        memory.push(resource_hob)
                    }
                }
                HOB_TYPE_GUID_EXTENSION => {
                    let guided_hob: GuidExtension = hob.pread(0).ok()?;
                    let hob_data = hob::get_guid_data(hob)?;
                    if &guided_hob.name == TD_KERNEL_INFO_HOB_GUID.as_bytes() {
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
            offset = hob::align_to_next_hob_offset(raw.len(), offset, header.length)?;
        }
        Some(Self {
            payload_info,
            payload_param,
            acpi_tables,
            memory,
        })
    }
}

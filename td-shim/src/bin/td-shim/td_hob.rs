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
                        || resource_hob.resource_type == RESOURCE_MEMORY_UNACCEPTED
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

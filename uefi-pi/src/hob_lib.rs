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

use core::mem::size_of;
use r_uefi_pi::hob::*;
use scroll::Pread;

const SIZE_4G: u64 = 0x100000000u64;

pub fn align_hob(v: u16) -> u16 {
    (v + 7) / 8 * 8
}

pub fn dump_hob(hob_list: &[u8]) {
    let mut offset = 0;

    loop {
        let hob = &hob_list[offset..];
        let header: Header = hob.pread(0).unwrap();
        match header.r#type {
            HOB_TYPE_HANDOFF => {
                let phit_hob: HandoffInfoTable = hob.pread(0).unwrap();
                phit_hob.dump();
            }
            HOB_TYPE_RESOURCE_DESCRIPTOR => {
                let resource_hob: ResourceDescription = hob.pread(0).unwrap();
                resource_hob.dump();
            }
            HOB_TYPE_MEMORY_ALLOCATION => {
                let allocation_hob: MemoryAllocation = hob.pread(0).unwrap();
                allocation_hob.dump();
            }
            HOB_TYPE_FV => {
                let fv_hob: FirmwareVolume = hob.pread(0).unwrap();
                fv_hob.dump();
            }
            HOB_TYPE_CPU => {
                let cpu_hob: Cpu = hob.pread(0).unwrap();
                cpu_hob.dump();
            }
            HOB_TYPE_END_OF_HOB_LIST => {
                break;
            }
            _ => {
                header.dump();
            }
        }
        offset += align_hob(header.length) as usize;
    }
}

/// used for data storage (stack/heap/pagetable/eventlog/...)
pub fn get_system_memory_size_below_4gb(hob_list: &[u8]) -> Option<u64> {
    let mut low_mem_top = 0u64; // TOLUD (top of low usable dram)
    let mut offset = 0;

    loop {
        let header: Header = hob_list.pread(offset).ok()?;

        match header.r#type {
            HOB_TYPE_RESOURCE_DESCRIPTOR => {
                let resource_hob: ResourceDescription = hob_list.pread(offset).unwrap();
                if resource_hob.resource_type == RESOURCE_SYSTEM_MEMORY {
                    let end = resource_hob
                        .physical_start
                        .checked_add(resource_hob.resource_length)?;
                    if end < SIZE_4G && end > low_mem_top {
                        low_mem_top = end;
                    }
                }
            }
            HOB_TYPE_END_OF_HOB_LIST => {
                break;
            }
            _ => {}
        }
        if header.length == 0 || header.length > (u16::MAX - 7) {
            return None;
        }

        offset = offset.checked_add(align_hob(header.length) as usize)? as usize;
    }

    Some(low_mem_top)
}

/// used for page table setup
pub fn get_total_memory_top(hob_list: &[u8]) -> u64 {
    let mut mem_top = 0; // TOM (top of memory)

    let mut offset = 0;

    loop {
        let header: Header = hob_list.pread(offset).unwrap();
        match header.r#type {
            HOB_TYPE_RESOURCE_DESCRIPTOR => {
                let resource_hob: ResourceDescription = hob_list.pread(offset).unwrap();
                if resource_hob.resource_type == RESOURCE_SYSTEM_MEMORY
                    || resource_hob.resource_type == RESOURCE_MEMORY_MAPPED_IO
                {
                    let end = resource_hob.physical_start + resource_hob.resource_length;
                    if end > mem_top {
                        mem_top = end;
                    }
                }
            }
            HOB_TYPE_END_OF_HOB_LIST => {
                break;
            }
            _ => {}
        }
        if header.length == 0 || header.length > (u16::MAX - 7) {
            break;
        }
        offset += align_hob(header.length) as usize;
    }
    mem_top
}

pub fn get_fv(hob_list: &[u8]) -> Option<FirmwareVolume> {
    let mut offset = 0;

    loop {
        let header: Header = hob_list.pread(offset).ok()?;

        match header.r#type {
            HOB_TYPE_FV => {
                let fv_hob: FirmwareVolume = hob_list.pread(offset).ok()?;
                return Some(fv_hob);
            }
            HOB_TYPE_END_OF_HOB_LIST => {
                break;
            }
            _ => {}
        }
        if header.length == 0 || header.length > (u16::MAX - 7) {
            return None;
        }
        offset = offset.checked_add(align_hob(header.length) as usize)? as usize;
    }
    None
}

pub fn get_hob_total_size(hob: &[u8]) -> Option<usize> {
    let phit: HandoffInfoTable = hob.pread(0).ok()?;
    Some(phit.efi_end_of_hob_list.checked_sub(hob.as_ptr() as u64)? as usize)
}

pub fn get_next_extension_guid_hob<'a>(hob_list: &'a [u8], guid: &[u8]) -> Option<&'a [u8]> {
    let mut offset = 0;

    loop {
        let header: Header = hob_list.pread(offset).ok()?;

        match header.r#type {
            HOB_TYPE_GUID_EXTENSION => {
                let guid_hob: GuidExtension = hob_list.pread(offset).ok()?;
                if guid_hob.name == guid[0..16] {
                    return Some(&hob_list[offset..]);
                }
            }
            HOB_TYPE_END_OF_HOB_LIST => {
                break;
            }
            _ => {}
        }
        if header.length == 0 || header.length > (u16::MAX - 7) {
            return None;
        }
        offset = offset.checked_add(align_hob(header.length) as usize)? as usize;
    }
    None
}

pub fn get_guid_data(hob_list: &'_ [u8]) -> Option<&'_ [u8]> {
    let mut offset = 0;

    let guid_hob: GuidExtension = hob_list.pread(offset).ok()?;
    offset = offset.checked_add(size_of::<GuidExtension>())?;

    let guid_data_len = guid_hob
        .header
        .length
        .checked_sub(size_of::<GuidExtension>() as u16)? as usize;
    hob_list
        .len()
        .checked_sub(offset.checked_add(guid_data_len)?)?;
    Some(&hob_list[offset..offset + guid_data_len])
}

pub fn get_nex_hob(hob_list: &'_ [u8]) -> Option<&'_ [u8]> {
    let header: Header = hob_list.pread(0).ok()?;
    (u16::MAX - 7).checked_sub(header.length)?;
    hob_list
        .len()
        .checked_sub(align_hob(header.length) as usize)?;
    Some(&hob_list[align_hob(header.length) as usize..])
}

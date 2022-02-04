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

/// Validate and align to next HOB header position.
pub fn align_to_next_hob_offset(cap: usize, offset: usize, length: u16) -> Option<usize> {
    if length == 0 || length > (u16::MAX - 7) {
        None
    } else {
        let offset = offset.checked_add((length as usize + 7) / 8 * 8)?;
        if offset < cap {
            Some(offset)
        } else {
            None
        }
    }
}

/// Seek to next available HOB entry in the buffer.
pub fn seek_to_next_hob(hob_list: &'_ [u8]) -> Option<&'_ [u8]> {
    let header: Header = hob_list.pread(0).ok()?;
    let offset = align_to_next_hob_offset(hob_list.len(), 0, header.length)?;

    Some(&hob_list[offset..])
}

/// Get size of the HOB list.
///
/// The caller needs to verify that the returned size is valid.
pub fn get_hob_total_size(hob: &[u8]) -> Option<usize> {
    let phit: HandoffInfoTable = hob.pread(0).ok()?;
    if phit.header.r#type == HOB_TYPE_HANDOFF
        && phit.header.length as usize >= size_of::<HandoffInfoTable>()
    {
        let end = phit.efi_end_of_hob_list.checked_sub(hob.as_ptr() as u64)?;
        if end < usize::MAX as u64 {
            Some(end as usize)
        } else {
            None
        }
    } else {
        None
    }
}

/// Dump the HOB list.
pub fn dump_hob(hob_list: &[u8]) -> Option<()> {
    let mut offset = 0;

    loop {
        let hob = &hob_list[offset..];
        let header: Header = hob.pread(0).ok()?;

        match header.r#type {
            HOB_TYPE_HANDOFF => {
                let phit_hob: HandoffInfoTable = hob.pread(0).ok()?;
                phit_hob.dump();
            }
            HOB_TYPE_RESOURCE_DESCRIPTOR => {
                let resource_hob: ResourceDescription = hob.pread(0).ok()?;
                resource_hob.dump();
            }
            HOB_TYPE_MEMORY_ALLOCATION => {
                let allocation_hob: MemoryAllocation = hob.pread(0).ok()?;
                allocation_hob.dump();
            }
            HOB_TYPE_FV => {
                let fv_hob: FirmwareVolume = hob.pread(0).ok()?;
                fv_hob.dump();
            }
            HOB_TYPE_CPU => {
                let cpu_hob: Cpu = hob.pread(0).ok()?;
                cpu_hob.dump();
            }
            HOB_TYPE_END_OF_HOB_LIST => return Some(()),
            _ => header.dump(),
        }

        offset = align_to_next_hob_offset(hob_list.len(), offset, header.length)?;
    }
}

/// Find Top of Lower Memory, which is the highest system memory address below 4G.
///
/// The low memory will be used for data storage (stack/heap/pagetable/eventlog/...)
pub fn get_system_memory_size_below_4gb(hob_list: &[u8]) -> Option<u64> {
    let mut low_mem_top = 0u64; // TOLUD (top of low usable dram)
    let mut offset = 0;

    loop {
        let hob = &hob_list[offset..];
        let header: Header = hob.pread(0).ok()?;

        match header.r#type {
            HOB_TYPE_RESOURCE_DESCRIPTOR => {
                let resource_hob: ResourceDescription = hob.pread(0).ok()?;
                if resource_hob.resource_type == RESOURCE_SYSTEM_MEMORY {
                    let end = resource_hob
                        .physical_start
                        .checked_add(resource_hob.resource_length)?;
                    if end < SIZE_4G && end > low_mem_top {
                        low_mem_top = end;
                    }
                }
            }
            HOB_TYPE_END_OF_HOB_LIST => break,
            _ => {}
        }

        offset = align_to_next_hob_offset(hob_list.len(), offset, header.length)?;
    }

    Some(low_mem_top)
}

/// Find Top of Memory, which is the highest system memory address below 4G.
pub fn get_total_memory_top(hob_list: &[u8]) -> Option<u64> {
    let mut mem_top = 0; // TOM (top of memory)
    let mut offset = 0;

    loop {
        let hob = &hob_list[offset..];
        let header: Header = hob.pread(0).ok()?;

        match header.r#type {
            HOB_TYPE_RESOURCE_DESCRIPTOR => {
                let resource_hob: ResourceDescription = hob.pread(0).ok()?;
                // TODO: why is RESOURCE_MEMORY_MAPPED_IO included for memory?
                if resource_hob.resource_type == RESOURCE_SYSTEM_MEMORY
                    || resource_hob.resource_type == RESOURCE_MEMORY_MAPPED_IO
                {
                    let end = resource_hob
                        .physical_start
                        .checked_add(resource_hob.resource_length)?;
                    if end > mem_top {
                        mem_top = end;
                    }
                }
            }
            HOB_TYPE_END_OF_HOB_LIST => break,
            _ => {}
        }
        offset = align_to_next_hob_offset(hob_list.len(), offset, header.length)?;
    }

    Some(mem_top)
}

pub fn get_fv(hob_list: &[u8]) -> Option<FirmwareVolume> {
    let mut offset = 0;

    loop {
        let hob = &hob_list[offset..];
        let header: Header = hob.pread(0).ok()?;
        match header.r#type {
            HOB_TYPE_FV => {
                let fv_hob: FirmwareVolume = hob.pread(0).ok()?;
                return Some(fv_hob);
            }
            HOB_TYPE_END_OF_HOB_LIST => break,
            _ => {}
        }
        offset = align_to_next_hob_offset(hob_list.len(), offset, header.length)?;
    }

    None
}

/// Find a GUID HOB entry matching `guid`.
pub fn get_next_extension_guid_hob<'a>(hob_list: &'a [u8], guid: &[u8]) -> Option<&'a [u8]> {
    let mut offset = 0;

    loop {
        let hob = &hob_list[offset..];
        let header: Header = hob.pread(0).ok()?;

        match header.r#type {
            HOB_TYPE_GUID_EXTENSION => {
                let guid_hob: GuidExtension = hob.pread(0).ok()?;
                if &guid_hob.name == guid {
                    return Some(hob);
                }
            }
            HOB_TYPE_END_OF_HOB_LIST => break,
            _ => {}
        }
        offset = align_to_next_hob_offset(hob_list.len(), offset, header.length)?;
    }
    None
}

/// Get content of a GUID HOB entry.
pub fn get_guid_data(hob_list: &[u8]) -> Option<&[u8]> {
    let guid_hob: GuidExtension = hob_list.pread(0).ok()?;
    let offset = size_of::<GuidExtension>();
    let end = guid_hob.header.length as usize;

    if end >= offset && end <= hob_list.len() {
        Some(&hob_list[offset..end])
    } else {
        None
    }
}

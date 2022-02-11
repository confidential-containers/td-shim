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

//! Functions to access UEFI-PI defined `Hand-Off Block` (HOB) list.

use core::mem::size_of;
use scroll::Pread;

use crate::pi::hob::*;

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
                if guid_hob.name == guid {
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::slice_from_raw_parts;

    #[test]
    fn test_align_to_next_hob() {
        assert!(align_to_next_hob_offset(usize::MAX, 0, 0).is_none());
        assert!(align_to_next_hob_offset(8, 8, 1).is_none());
        assert_eq!(align_to_next_hob_offset(usize::MAX, 8, 1), Some(16));
        assert_eq!(align_to_next_hob_offset(usize::MAX, 8, 9), Some(24));
        assert_eq!(
            align_to_next_hob_offset(usize::MAX, 0, u16::MAX - 8),
            Some(u16::MAX as usize - 7)
        );
        assert_eq!(
            align_to_next_hob_offset(usize::MAX, 0, u16::MAX - 7),
            Some(u16::MAX as usize - 7)
        );
        assert_eq!(
            align_to_next_hob_offset(usize::MAX, 8, u16::MAX - 7),
            Some(u16::MAX as usize + 1)
        );
        assert!(align_to_next_hob_offset(usize::MAX, 0, u16::MAX - 6).is_none());
        assert!(align_to_next_hob_offset(usize::MAX, 8, u16::MAX).is_none());
    }

    #[test]
    fn test_get_hob_total_size() {
        assert!(get_hob_total_size(&[]).is_none());

        let mut tbl = HandoffInfoTable {
            header: Header {
                r#type: HOB_TYPE_HANDOFF,
                length: size_of::<HandoffInfoTable>() as u16,
                reserved: 0,
            },
            version: 1,
            boot_mode: 0,
            efi_memory_top: 0x2_0000_0000,
            efi_memory_bottom: 0xc000_0000,
            efi_free_memory_top: 0,
            efi_free_memory_bottom: 0,
            efi_end_of_hob_list: 0,
        };
        let buf = unsafe {
            &*slice_from_raw_parts(
                &tbl as *const HandoffInfoTable as *const u8,
                size_of::<HandoffInfoTable>(),
            )
        };
        assert!(get_hob_total_size(buf).is_none());

        let end = &tbl as *const HandoffInfoTable as *const u8 as usize as u64 + 0x10000;
        tbl.efi_end_of_hob_list = end;
        assert_eq!(get_hob_total_size(buf), Some(0x10000));
    }

    #[test]
    fn test_dump_hob() {
        assert!(dump_hob(&[]).is_none());
        assert!(dump_hob(&[0u8]).is_none());
    }

    #[test]
    fn test_get_system_memory_size_below_4gb() {
        assert!(get_system_memory_size_below_4gb(&[]).is_none());

        let mut buf = [0u8; 1024];
        let res = ResourceDescription {
            header: Header {
                r#type: HOB_TYPE_RESOURCE_DESCRIPTOR,
                length: size_of::<ResourceDescription>() as u16,
                reserved: 0,
            },
            owner: [0u8; 16],
            resource_type: RESOURCE_SYSTEM_MEMORY,
            resource_attribute: 0,
            physical_start: 0,
            resource_length: 0x200_0000,
        };
        let buf1 = unsafe {
            &*slice_from_raw_parts(
                &res as *const ResourceDescription as *const u8,
                size_of::<ResourceDescription>(),
            )
        };
        buf[..size_of::<ResourceDescription>()].copy_from_slice(buf1);
        let res = ResourceDescription {
            header: Header {
                r#type: HOB_TYPE_RESOURCE_DESCRIPTOR,
                length: size_of::<ResourceDescription>() as u16,
                reserved: 0,
            },
            owner: [0u8; 16],
            resource_type: RESOURCE_SYSTEM_MEMORY,
            resource_attribute: 0,
            physical_start: 0x1000_0000,
            resource_length: 0x200_0000,
        };
        let buf1 = unsafe {
            &*slice_from_raw_parts(
                &res as *const ResourceDescription as *const u8,
                size_of::<ResourceDescription>(),
            )
        };
        buf[size_of::<ResourceDescription>()..2 * size_of::<ResourceDescription>()]
            .copy_from_slice(buf1);
        let end = Header {
            r#type: HOB_TYPE_END_OF_HOB_LIST,
            length: 0,
            reserved: 0,
        };
        let buf2 = unsafe {
            &*slice_from_raw_parts(&end as *const Header as *const u8, size_of::<Header>())
        };
        buf[2 * size_of::<ResourceDescription>()
            ..2 * size_of::<ResourceDescription>() + size_of::<Header>()]
            .copy_from_slice(buf2);
        assert_eq!(get_system_memory_size_below_4gb(&buf), Some(0x1200_0000));

        let res = ResourceDescription {
            header: Header {
                r#type: HOB_TYPE_RESOURCE_DESCRIPTOR,
                length: 0,
                reserved: 0,
            },
            owner: [0u8; 16],
            resource_type: RESOURCE_SYSTEM_MEMORY,
            resource_attribute: 0,
            physical_start: 0,
            resource_length: 0x200_0000,
        };
        let buf1 = unsafe {
            &*slice_from_raw_parts(
                &res as *const ResourceDescription as *const u8,
                size_of::<ResourceDescription>(),
            )
        };
        buf[..size_of::<ResourceDescription>()].copy_from_slice(buf1);
        assert!(get_system_memory_size_below_4gb(&buf).is_none());
    }

    #[test]
    fn test_get_fv() {
        assert!(get_fv(&[]).is_none());

        let mut buf = [0u8; 1024];
        let res = FirmwareVolume {
            header: Header {
                r#type: HOB_TYPE_FV,
                length: size_of::<FirmwareVolume>() as u16,
                reserved: 0,
            },
            base_address: 0x1000000,
            length: 0,
        };
        let buf1 = unsafe {
            &*slice_from_raw_parts(
                &res as *const FirmwareVolume as *const u8,
                size_of::<FirmwareVolume>(),
            )
        };
        buf[..size_of::<FirmwareVolume>()].copy_from_slice(buf1);
        let end = Header {
            r#type: HOB_TYPE_END_OF_HOB_LIST,
            length: 0,
            reserved: 0,
        };
        let buf2 = unsafe {
            &*slice_from_raw_parts(&end as *const Header as *const u8, size_of::<Header>())
        };
        buf[size_of::<FirmwareVolume>()..size_of::<FirmwareVolume>() + size_of::<Header>()]
            .copy_from_slice(buf2);
        assert!(get_fv(&buf).is_some());

        let res = FirmwareVolume {
            header: Header {
                r#type: HOB_TYPE_FV2,
                length: u16::MAX,
                reserved: 0,
            },
            base_address: 0x1000000,
            length: 0,
        };
        let buf1 = unsafe {
            &*slice_from_raw_parts(
                &res as *const FirmwareVolume as *const u8,
                size_of::<FirmwareVolume>(),
            )
        };
        buf[..size_of::<FirmwareVolume>()].copy_from_slice(buf1);
        assert!(get_fv(&buf).is_none());
    }

    #[test]
    fn test_get_guid() {
        assert!(get_next_extension_guid_hob(&[], &[0u8; 16]).is_none());

        let mut buf = [0xaau8; 128];
        let res = GuidExtension {
            header: Header {
                r#type: HOB_TYPE_GUID_EXTENSION,
                length: size_of::<GuidExtension>() as u16 + 16,
                reserved: 0,
            },
            name: [0xa5u8; 16],
        };
        let buf1 = unsafe {
            &*slice_from_raw_parts(
                &res as *const GuidExtension as *const u8,
                size_of::<GuidExtension>(),
            )
        };
        buf[..size_of::<GuidExtension>()].copy_from_slice(buf1);
        let end = Header {
            r#type: HOB_TYPE_END_OF_HOB_LIST,
            length: 0,
            reserved: 0,
        };
        let buf2 = unsafe {
            &*slice_from_raw_parts(&end as *const Header as *const u8, size_of::<Header>())
        };
        buf[size_of::<GuidExtension>() + 16..size_of::<GuidExtension>() + 16 + size_of::<Header>()]
            .copy_from_slice(buf2);
        let guid = get_next_extension_guid_hob(&buf, &[0xa5u8; 16]).unwrap();
        let data = get_guid_data(guid).unwrap();
        assert_eq!(data, &[0xaa; 16]);
    }
}

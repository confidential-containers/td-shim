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

// Check hob length equal efi_end_of_hob_list of HandoffInfoTable
pub fn check_hob_length(hob: &[u8], hob_length: usize) -> Option<&[u8]> {
    let phit: HandoffInfoTable = hob.pread(0).ok()?;
    let end: u64 = phit.efi_end_of_hob_list;
    if phit.header.r#type == HOB_TYPE_HANDOFF
        && phit.header.length as usize >= size_of::<HandoffInfoTable>()
    {
        if hob_length as u64 == end.checked_sub(hob.as_ptr() as u64)? {
            Some(&hob[0..hob_length])
        } else {
            None
        }
    } else {
        None
    }
}

// Check the integrity of HOB list that is got from untrusted input
// and return the HOB slice with real HOB length
pub fn check_hob_integrity(hob_list: &[u8]) -> Option<&[u8]> {
    let mut offset = 0;
    let hob_list_len = hob_list.len();

    // A valid HOB should have an HandoffInfoTable at least
    if hob_list_len < size_of::<HandoffInfoTable>() {
        return None;
    }
    speculation_barrier();

    loop {
        let hob = &hob_list[offset..];
        if offset + size_of::<Header>() > hob_list_len {
            return None;
        }
        speculation_barrier();

        let header: Header = hob.pread(0).ok()?;

        // A valid HOB should has non-zero length and zero reserved field,
        if header.length == 0 || header.length as usize > hob.len() || header.reserved != 0 {
            return None;
        }
        speculation_barrier();

        match header.r#type {
            HOB_TYPE_HANDOFF => {
                if header.length as usize != size_of::<HandoffInfoTable>()
                    || offset + size_of::<HandoffInfoTable>() > hob_list_len
                {
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
            HOB_TYPE_END_OF_HOB_LIST => {
                let hob_length = offset + size_of::<Header>();

                return check_hob_length(hob_list, hob_length);
            }
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
                if header.length as usize != size_of::<Cpu>()
                    || offset + size_of::<Cpu>() > hob_list_len
                {
                    return None;
                }

                let cpu_hob: Cpu = hob.pread(0).ok()?;
                // Reserved field is expected to be zero
                if cpu_hob.reserved != [0u8; 6] {
                    return None;
                }
            }
            HOB_TYPE_GUID_EXTENSION => {
                // GUID Extension HOB has variable length
            }
            // Unsupported types
            _ => return None,
        }
        offset = align_to_next_hob_offset(hob_list_len, offset, header.length)?;
        speculation_barrier();
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
    use crate::pi::guid::Guid;
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
    fn test_dump_hob() {
        assert!(dump_hob(&[]).is_none());
        assert!(dump_hob(&[0u8]).is_none());

        let memory_allocation_hob_header = Header {
            r#type: HOB_TYPE_MEMORY_ALLOCATION,
            length: size_of::<MemoryAllocation>() as u16,
            reserved: 0x0,
        };
        let memory_allocation_header = MemoryAllocationHeader {
            name: [0; 16],
            memory_base_address: 0x0,
            memory_length: 0x0,
            memory_type: 0x0,
            reserved: [0; 4],
        };
        let _ = memory_allocation_header.as_bytes();
        let hob = MemoryAllocation {
            header: memory_allocation_hob_header,
            alloc_descriptor: memory_allocation_header,
        };
        assert!(dump_hob(hob.as_bytes()).is_none());

        let fv_hob_header = Header {
            r#type: HOB_TYPE_FV,
            length: size_of::<FirmwareVolume>() as u16,
            reserved: 0x0,
        };
        let hob = FirmwareVolume {
            header: fv_hob_header,
            base_address: 0x0,
            length: 0x0,
        };
        assert!(dump_hob(hob.as_bytes()).is_none());

        let cpu_hob_header = Header {
            r#type: HOB_TYPE_CPU,
            length: size_of::<Cpu>() as u16,
            reserved: 0x0,
        };
        let hob = Cpu {
            header: cpu_hob_header,
            size_of_memory_space: 0x0,
            size_of_io_space: 0x0,
            reserved: [0; 6],
        };
        assert!(dump_hob(hob.as_bytes()).is_none());
    }

    #[test]
    fn test_check_hob_length() {
        let hob_header = Header {
            r#type: HOB_TYPE_HANDOFF,
            length: size_of::<HandoffInfoTable>() as u16,
            reserved: 0x0,
        };

        let mut hob = HandoffInfoTable {
            header: hob_header,
            version: 0,
            boot_mode: 0,
            efi_memory_top: 0,
            efi_memory_bottom: 0,
            efi_free_memory_top: 0,
            efi_free_memory_bottom: 0,
            efi_end_of_hob_list: 0,
        };
        hob.efi_end_of_hob_list =
            size_of::<HandoffInfoTable>() as u64 + hob.as_bytes().as_ptr() as u64;
        assert!(check_hob_length(hob.as_bytes(), size_of::<HandoffInfoTable>() as usize).is_some());
        // hob.efi_end_of_hob_list less than hob ptr
        hob.efi_end_of_hob_list = hob.as_bytes().as_ptr() as u64 - 1;
        assert!(check_hob_length(hob.as_bytes(), size_of::<HandoffInfoTable>() as usize).is_none());
        // hob_length + hob prt greater than u64::MAX
        hob.efi_end_of_hob_list =
            size_of::<HandoffInfoTable>() as u64 + hob.as_bytes().as_ptr() as u64;
        assert!(check_hob_length(hob.as_bytes(), u64::MAX as usize).is_none());

        // first header type is not HOB_TYPE_HANDOFF
        let hob_header = Header {
            r#type: HOB_TYPE_MEMORY_ALLOCATION,
            length: size_of::<HandoffInfoTable>() as u16,
            reserved: 0x0,
        };
        let mut hob = HandoffInfoTable {
            header: hob_header,
            version: 0,
            boot_mode: 0,
            efi_memory_top: 0,
            efi_memory_bottom: 0,
            efi_free_memory_top: 0,
            efi_free_memory_bottom: 0,
            efi_end_of_hob_list: 0,
        };
        hob.efi_end_of_hob_list =
            size_of::<HandoffInfoTable>() as u64 + hob.as_bytes().as_ptr() as u64;
        assert!(check_hob_length(hob.as_bytes(), size_of::<HandoffInfoTable>() as usize).is_none());

        // length less than HandoffInfoTable size
        let hob_header = Header {
            r#type: HOB_TYPE_HANDOFF,
            length: size_of::<HandoffInfoTable>() as u16 - 1,
            reserved: 0x0,
        };
        let mut hob = HandoffInfoTable {
            header: hob_header,
            version: 0,
            boot_mode: 0,
            efi_memory_top: 0,
            efi_memory_bottom: 0,
            efi_free_memory_top: 0,
            efi_free_memory_bottom: 0,
            efi_end_of_hob_list: 0,
        };
        hob.efi_end_of_hob_list =
            size_of::<HandoffInfoTable>() as u64 + hob.as_bytes().as_ptr() as u64;
        assert!(check_hob_length(hob.as_bytes(), size_of::<HandoffInfoTable>() as usize).is_none());
    }

    #[test]
    fn test_check_hob_integrity() {
        const EFI_END_OF_HOB_LIST_OFFSET: usize = 48;
        let hob = &include_bytes!("../fuzz/seeds/hob_parser/hob_buffer")[..];
        let mut test_hob = hob.to_vec();
        let ptr = test_hob.as_ptr() as u64;
        if test_hob.len() >= size_of::<HandoffInfoTable>() {
            test_hob[EFI_END_OF_HOB_LIST_OFFSET..size_of::<HandoffInfoTable>()]
                .copy_from_slice(&u64::to_le_bytes(ptr + hob.len() as u64)[..]);
        }

        assert!(check_hob_integrity(&test_hob).is_some());
        assert!(dump_hob(&test_hob).is_some());
    }

    #[test]
    fn test_get_total_memory_top() {
        let hob = &include_bytes!("../fuzz/seeds/hob_parser/hob_buffer")[..];

        assert!(get_total_memory_top(hob).is_some());
    }

    #[test]
    fn test_seek_to_next_hob() {
        let hob = &include_bytes!("../fuzz/seeds/hob_parser/hob_buffer")[..];

        assert!(seek_to_next_hob(hob).is_some());
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
        let guid = Guid::from_bytes(&[0u8; 16]);
        assert!(get_next_extension_guid_hob(&[], guid.as_bytes()).is_none());

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
        assert_eq!(buf1, res.as_bytes());
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

// To protect against speculative attacks, place the LFENCE instruction after the range
// check and branch, but before any code that consumes the checked value.
fn speculation_barrier() {
    unsafe { core::arch::asm!("lfence") }
}

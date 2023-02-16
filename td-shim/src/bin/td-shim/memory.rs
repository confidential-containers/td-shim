// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use core::panic;
use td_layout::memslice::SliceType;
use td_layout::{build_time::*, runtime::*, *};
use td_shim::e820::{E820Entry, E820Type};
use td_shim::{PayloadInfo, TdPayloadInfoHobType};
use td_uefi_pi::hob;
use td_uefi_pi::pi::hob::{
    ResourceDescription, RESOURCE_MEMORY_RESERVED, RESOURCE_MEMORY_UNACCEPTED,
    RESOURCE_SYSTEM_MEMORY,
};
use x86_64::{
    structures::paging::PageTableFlags as Flags,
    structures::paging::{OffsetPageTable, PageTable},
    PhysAddr, VirtAddr,
};

use crate::e820::E820Table;
use crate::td;

const EXTENDED_FUNCTION_INFO: u32 = 0x80000000;
const VIRT_PHYS_MEM_SIZES: u32 = 0x80000008;
const MEMORY_4G: u64 = 0x1_0000_0000;
const SIZE_2M: u64 = 0x200000;
const RESERVED_MEMORY_SPACE_SIZE: u64 = 0x400_0000;

pub struct Memory<'a> {
    layout: RuntimeMemoryLayout,
    pt: OffsetPageTable<'a>,
    pub regions: Vec<ResourceDescription>,
}

impl<'a> Memory<'a> {
    pub fn new(
        resources: &[ResourceDescription],
        payload_info: Option<PayloadInfo>,
    ) -> Option<Self> {
        // Init memory resources
        let regions = Self::init_memory_resources(resources);
        let payload_type = payload_info
            .map(|info| info.image_type.into())
            .unwrap_or(TdPayloadInfoHobType::ExecutablePayload);

        // Look for the top region with appropriate size above the
        // low memory and below 4G.
        let mut tolm = regions
            .iter()
            .map(|entry| {
                let entry_top = entry.physical_start + entry.resource_length;
                if entry.resource_type == RESOURCE_SYSTEM_MEMORY && entry_top < MEMORY_4G {
                    entry_top
                } else {
                    0
                }
            })
            .max()?;

        let layout_config = match payload_type {
            TdPayloadInfoHobType::ExecutablePayload => runtime::exec::MEMORY_LAYOUT_CONFIG,
            TdPayloadInfoHobType::BzImage | TdPayloadInfoHobType::RawVmLinux => {
                runtime::linux::MEMORY_LAYOUT_CONFIG
            }
            TdPayloadInfoHobType::UnknownImage => return None,
        };
        let layout = RuntimeMemoryLayout::new(tolm as usize, layout_config)?;

        let page_table_address = layout
            .get_region(SliceType::PayloadPageTable)
            .expect("Unable to get page table slice")
            .base_address;
        // Create an offset page table instance to manage the paging
        let pt = unsafe {
            OffsetPageTable::new(
                &mut *(page_table_address as *mut PageTable),
                VirtAddr::new(td_paging::PHYS_VIRT_OFFSET as u64),
            )
        };

        Some(Memory {
            pt,
            layout,
            regions,
        })
    }

    // - Frame size for runtime memory region is 4K bytes since page-table
    //   level protections are used such as no-execute protection.
    // - Frame size for other memory region is 1G bytes.
    pub fn setup_paging(&mut self) {
        // Init frame allocator
        let page_table_region = self.get_layout_region(SliceType::PayloadPageTable);
        td_paging::init(
            page_table_region.base_address as u64,
            page_table_region.size,
        );

        // Create mapping for 0 - base address of runtime layout region
        td_paging::create_mapping(
            &mut self.pt,
            PhysAddr::new(0),
            VirtAddr::new(0),
            td_paging::PAGE_SIZE_DEFAULT as u64,
            MEMORY_4G,
        )
        .expect("Fail to map 0 to runtime memory bottom");

        // Setup page table only for system memory resources higher than 4G
        for m in &self.regions {
            let r_end = m.physical_start + m.resource_length;
            if r_end <= MEMORY_4G as u64 {
                continue;
            } else {
                td_paging::create_mapping(
                    &mut self.pt,
                    PhysAddr::new(m.physical_start),
                    VirtAddr::new(m.physical_start),
                    td_paging::PAGE_SIZE_DEFAULT as u64,
                    m.resource_length,
                )
                .expect("Fail to map memory region upper 4G");
            }
        }

        td_paging::cr3_write(
            self.get_layout_region(SliceType::PayloadPageTable)
                .base_address as u64,
        );
    }

    pub fn create_e820(&self) -> E820Table {
        let mut table = E820Table::new();
        for r in &self.regions {
            table.add_range(E820Type::Memory, r.physical_start, r.resource_length);
        }

        for r in self.layout.regions() {
            let e820_type: E820Type = r.r#type.into();
            if e820_type != E820Type::Memory {
                table.convert_range(r.r#type.into(), r.base_address as u64, r.size as u64);
            }
        }

        table
    }

    pub fn get_dynamic_mem_slice(&self, name: SliceType) -> &'static [u8] {
        unsafe {
            self.layout
                .get_mem_slice(name)
                .unwrap_or_else(|| panic!("Unable to get {} slice", name))
        }
    }

    pub fn get_dynamic_mem_slice_mut(&self, name: SliceType) -> &'static mut [u8] {
        // Safe because we are the only user in single-thread context.
        unsafe {
            self.layout
                .get_mem_slice_mut(name)
                .unwrap_or_else(|| panic!("Unable to get {} slice", name))
        }
    }

    pub fn get_layout_region(&self, name: SliceType) -> LayoutRegion {
        // Safe because we are the only user in single-thread context.
        self.layout
            .get_region(name)
            .unwrap_or_else(|| panic!("Unable to get information about {} memory region", name))
    }

    fn init_memory_resources(resources: &[ResourceDescription]) -> Vec<ResourceDescription> {
        let mut regions: Vec<ResourceDescription> = Vec::new();
        let support_unaccepted = Self::support_unaccepted_type(resources);

        for entry in resources {
            let entry_top = entry.physical_start + entry.resource_length;
            let mut new = *entry;

            // Do not count the memory in reserved range into total memory size
            // VMM may reserve memory in this region for some special reason.
            // For example, QEMU may reserve 4 pages at 0xfeffc000 for an EPT
            // identity map and a TSS in order to use vm86 mode to emulate
            // 16-bit code directly.
            if new.physical_start >= MEMORY_4G - RESERVED_MEMORY_SPACE_SIZE
                && new.physical_start + new.resource_length < MEMORY_4G
            {
                continue;
            }

            // To be compatible with the legacy resource types
            if !support_unaccepted {
                if new.resource_type == RESOURCE_SYSTEM_MEMORY {
                    new.resource_type = RESOURCE_MEMORY_UNACCEPTED;
                } else if new.resource_type == RESOURCE_MEMORY_RESERVED {
                    new.resource_type = RESOURCE_SYSTEM_MEMORY;
                }
            }

            // Filter out the resources covers image space
            // TBD: it should be ensured by VMM that this kind of resources should be MMIO
            if new.physical_start >= TD_SHIM_FIRMWARE_BASE as u64 && new.physical_start < MEMORY_4G
            {
                if entry_top > MEMORY_4G {
                    if new.resource_type == RESOURCE_SYSTEM_MEMORY
                        || new.resource_type == RESOURCE_MEMORY_UNACCEPTED
                    {
                        new.physical_start = MEMORY_4G;
                        new.resource_length = entry_top - MEMORY_4G;
                    }
                } else {
                    continue;
                }
            }

            regions.push(new);
        }

        #[cfg(feature = "tdx")]
        Self::accept_memory_resources(&mut regions);

        regions
    }

    // This function is used to check if the HOB contains the RESOURCE_MEMORY_UNACCEPTED
    // type resource.
    // For old version VMM, it reports the unaccepted memory as RESOURCE_SYSTEM_MEMORY
    // and private memory as RESOURCE_MEMORY_RESERVED.
    // Newer version VMM will report the unaccepted memory as RESOURCE_MEMORY_UNACCEPTED,
    // and private memory as RESOURCE_SYSTEM_MEMORY.
    fn support_unaccepted_type(resources: &[ResourceDescription]) -> bool {
        for entry in resources {
            if entry.resource_type == RESOURCE_MEMORY_UNACCEPTED {
                return true;
            }
        }
        false
    }

    #[cfg(all(feature = "tdx"))]
    /// Build a 2M granularity bitmap for kernel to track the unaccepted memory
    pub fn build_unaccepted_memory_bitmap(&self) -> u64 {
        #[cfg(not(feature = "lazy-accept"))]
        return 0;

        let bitmap = self.get_dynamic_mem_slice_mut(memslice::SliceType::UnacceptedMemoryBitmap);

        for region in self.regions.as_slice() {
            if region.resource_type == RESOURCE_MEMORY_UNACCEPTED {
                let mut start = region.physical_start;
                let mut end = region.physical_start + region.resource_length;

                if region.resource_length < SIZE_2M {
                    td::accept_memory_resource_range(start, region.resource_length);
                    continue;
                }

                // Accept memory to align the 'start' up to 2M
                if start & (SIZE_2M - 1) != 0 {
                    td::accept_memory_resource_range(start, SIZE_2M - (start % SIZE_2M));
                    start += SIZE_2M;
                }
                start /= SIZE_2M;

                // Accept memory to align the 'end' down to 2M
                if end & (SIZE_2M - 1) != 0 {
                    td::accept_memory_resource_range(end - (end % SIZE_2M), end % SIZE_2M);
                }
                end /= SIZE_2M;

                // Set the bit for the unaccepted memory range [start, end)
                for index in start..end {
                    bitmap[(index / 8) as usize] |= 1 << (index % 8);
                }
            }
        }

        self.get_layout_region(SliceType::UnacceptedMemoryBitmap)
            .base_address as u64
    }

    #[cfg(feature = "tdx")]
    fn accept_memory_resources(resources: &mut Vec<ResourceDescription>) {
        use td_layout::TD_PAYLOAD_PARTIAL_ACCEPT_MEMORY_SIZE;
        use td_uefi_pi::pi;

        // The physical address must not exceed the shared mask (the last bit of GPAW).
        let (index, max_phys_addr) = resources
            .iter()
            .enumerate()
            .map(|(index, resource)| {
                (
                    index,
                    resource.physical_start + resource.resource_length - 1,
                )
            })
            .max_by(|cur, next| cur.1.cmp(&next.1))
            .unwrap();
        let shared_mask = td::get_shared_page_mask();
        if max_phys_addr > shared_mask {
            panic!(
                "Invalid physical address in resource {:x?}.
                The maximum physical address is {:x} while the it should be less than {:x}",
                resources[index], max_phys_addr, shared_mask
            );
        }

        let mut to_be_accepted = u64::MAX;
        #[cfg(feature = "lazy-accept")]
        let mut to_be_accepted = TD_PAYLOAD_PARTIAL_ACCEPT_MEMORY_SIZE as u64;

        for idx in 0..resources.len() {
            if resources[idx].resource_type == pi::hob::RESOURCE_MEMORY_UNACCEPTED {
                let size = if resources[idx].resource_length > to_be_accepted {
                    // Update start address and the length of the current region
                    // and insert a new resource descriptor for the unaccepted part.
                    let mut new = resources[idx];
                    new.physical_start += to_be_accepted;
                    new.resource_length -= to_be_accepted;
                    resources.insert(idx + 1, new);

                    resources[idx].resource_length = to_be_accepted;
                    resources[idx].resource_type = RESOURCE_SYSTEM_MEMORY;

                    to_be_accepted
                } else {
                    resources[idx].resource_type = RESOURCE_SYSTEM_MEMORY;
                    resources[idx].resource_length
                };
                if to_be_accepted > 0 {
                    td::accept_memory_resource_range(resources[idx].physical_start, size);
                    to_be_accepted -= size;
                }
            }
        }
    }

    pub fn set_write_protect(&mut self, address: u64, size: u64) {
        let flags = Flags::PRESENT | Flags::USER_ACCESSIBLE;

        td_paging::set_page_flags(&mut self.pt, VirtAddr::new(address), size as i64, flags);
    }

    pub fn set_shared_bit(&mut self, address: u64, size: u64) {
        let shared_page_flag = td::get_shared_page_mask();
        let mut flags = Flags::PRESENT | Flags::WRITABLE;
        flags = unsafe { Flags::from_bits_unchecked(flags.bits() | shared_page_flag) };

        td_paging::set_page_flags(&mut self.pt, VirtAddr::new(address), size as i64, flags);
    }

    pub fn set_nx_bit(&mut self, address: u64, size: u64) {
        let flags = Flags::PRESENT | Flags::WRITABLE | Flags::USER_ACCESSIBLE | Flags::NO_EXECUTE;

        td_paging::set_page_flags(&mut self.pt, VirtAddr::new(address), size as i64, flags);
    }

    pub fn set_not_present(&mut self, address: u64, size: u64) {
        let flags: Flags = Flags::empty();

        td_paging::set_page_flags(&mut self.pt, VirtAddr::new(address), size as i64, flags);
    }
}

// Find the top memory address of the system memory resources
fn memory_top(resources: &[ResourceDescription]) -> u64 {
    let mut memory_top = 0;
    for region in resources {
        if region.resource_type == RESOURCE_MEMORY_UNACCEPTED
            || region.resource_type == RESOURCE_SYSTEM_MEMORY
        {
            let entry_top = region.physical_start + region.resource_length;
            if entry_top > memory_top {
                memory_top = entry_top;
            }
        }
    }

    memory_top
}

/// Get the maximum physical memory addressability of the processor.
pub fn cpu_get_memory_space_size() -> u8 {
    let cpuid = unsafe { core::arch::x86_64::__cpuid(EXTENDED_FUNCTION_INFO) };
    let size_of_mem_space = if cpuid.eax >= VIRT_PHYS_MEM_SIZES {
        let cpuid = unsafe { core::arch::x86_64::__cpuid(VIRT_PHYS_MEM_SIZES) };
        // CPUID.80000008H:EAX[bits 7-0]: the size of the physical address range
        cpuid.eax as u8
    } else {
        // fallback value according to edk2 core
        36
    };

    log::info!(
        "Maximum physical memory addressability of the processor - {}\n",
        size_of_mem_space
    );

    size_of_mem_space
}

#[cfg(test)]
mod tests {
    use super::*;
    use td_layout::runtime;

    #[test]
    fn test_constants() {
        // Ensure the runtime layout has reserved enough space for page table pages.
        assert!(
            PAGE_TABLE_SIZE as u64
                <= runtime::TD_PAYLOAD_PARAM_BASE - runtime::TD_PAYLOAD_PAGE_TABLE_BASE
        );
    }
}

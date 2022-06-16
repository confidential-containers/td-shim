// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use td_layout::build_time::{TD_SHIM_FIRMWARE_BASE, TD_SHIM_FIRMWARE_SIZE};
use td_layout::runtime::{
    self, TD_PAYLOAD_BASE, TD_PAYLOAD_EVENT_LOG_SIZE, TD_PAYLOAD_PAGE_TABLE_BASE,
    TD_PAYLOAD_PAGE_TABLE_SIZE, TD_PAYLOAD_SIZE,
};
use td_layout::{memslice, RuntimeMemoryLayout, MIN_MEMORY_SIZE};
use td_shim::e820::{E820Entry, E820Type};
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
const LOW_MEM_TOP: u64 = TD_PAYLOAD_BASE + TD_PAYLOAD_SIZE as u64;
const SIZE_2M: u64 = 0x200000;

pub struct Memory<'a> {
    pub layout: RuntimeMemoryLayout,
    pt: OffsetPageTable<'a>,
    pub regions: Vec<ResourceDescription>,
}

impl<'a> Memory<'a> {
    pub fn new(resources: &[ResourceDescription]) -> Option<Self> {
        // Init memory resources
        let regions = Self::init_memory_resources(resources);

        // Look for the top region with appropriate size above the
        // low memory and below 4G.
        let mut runtime_top = 0;
        for entry in &regions {
            let entry_top = entry.physical_start + entry.resource_length;
            if entry.resource_type == RESOURCE_SYSTEM_MEMORY
                && entry_top - MIN_MEMORY_SIZE >= LOW_MEM_TOP
                && entry_top < MEMORY_4G
                && entry.resource_length >= MIN_MEMORY_SIZE
                && entry_top > runtime_top
            {
                runtime_top = entry_top;
            }
        }
        // Create the runtime layout if a suitable memory region can be found
        if runtime_top == 0 {
            return None;
        }
        let layout = RuntimeMemoryLayout::new(runtime_top);

        // Create an offset page table instance to manage the paging
        let pt = unsafe {
            OffsetPageTable::new(
                &mut *(TD_PAYLOAD_PAGE_TABLE_BASE as *mut PageTable),
                VirtAddr::new(td_paging::PHYS_VIRT_OFFSET as u64),
            )
        };

        Some(Memory {
            pt,
            layout,
            regions,
        })
    }

    pub fn setup_paging(&mut self) {
        // Init frame allocator
        td_paging::init(TD_PAYLOAD_PAGE_TABLE_BASE, TD_PAYLOAD_PAGE_TABLE_SIZE);
        // Create mapping for firmware image space
        td_paging::create_mapping(
            &mut self.pt,
            PhysAddr::new(TD_SHIM_FIRMWARE_BASE as u64),
            VirtAddr::new(TD_SHIM_FIRMWARE_BASE as u64),
            td_paging::PAGE_SIZE_4K as u64,
            TD_SHIM_FIRMWARE_SIZE as u64,
        );

        // Setup page table only for system memory resources
        // - Frame size below 4G is 4K bytes since we will configure page-table
        //   level protection for some spaces under 4G.
        // - Frame size upper 4G is 1G bytes.
        for m in &self.regions {
            let r_end = m.physical_start + m.resource_length;
            if r_end < MEMORY_4G as u64 {
                td_paging::create_mapping(
                    &mut self.pt,
                    PhysAddr::new(m.physical_start),
                    VirtAddr::new(m.physical_start),
                    td_paging::PAGE_SIZE_4K as u64,
                    m.resource_length,
                );
            } else {
                td_paging::create_mapping(
                    &mut self.pt,
                    PhysAddr::new(m.physical_start),
                    VirtAddr::new(m.physical_start),
                    td_paging::PAGE_SIZE_DEFAULT as u64,
                    m.resource_length,
                );
            }
        }

        // Setup page-table level protection
        // - Enable Non-Excutable for non-code spaces
        // - Set Shared bit for DMA memory in TDX
        self.set_nx_bit(
            self.layout.runtime_memory_bottom,
            self.layout.runtime_memory_top - self.layout.runtime_memory_bottom,
        );

        td_paging::cr3_write();
    }

    pub fn create_e820(&self) -> E820Table {
        let mut table = E820Table::new();
        for r in &self.regions {
            table.add_range(E820Type::Memory, r.physical_start, r.resource_length);
        }

        table.convert_range(
            E820Type::Acpi,
            self.layout.runtime_acpi_base,
            runtime::TD_PAYLOAD_ACPI_SIZE as u64,
        );
        table.convert_range(
            E820Type::Nvs,
            self.layout.runtime_event_log_base,
            runtime::TD_PAYLOAD_EVENT_LOG_SIZE as u64,
        );
        table.convert_range(
            E820Type::Nvs,
            self.layout.runtime_mailbox_base as u64,
            runtime::TD_PAYLOAD_MAILBOX_SIZE as u64,
        );

        table
    }

    fn init_memory_resources(resources: &[ResourceDescription]) -> Vec<ResourceDescription> {
        let mut regions: Vec<ResourceDescription> = Vec::new();

        for entry in resources {
            let entry_top = entry.physical_start + entry.resource_length;
            let mut new = *entry;

            // Filter out the resources covers image space
            // TBD: it should be ensured by VMM that this kind of resources should be MMIO
            if new.physical_start >= TD_SHIM_FIRMWARE_BASE as u64 && new.physical_start < MEMORY_4G
            {
                if entry_top > MEMORY_4G {
                    if new.resource_type == RESOURCE_SYSTEM_MEMORY {
                        new.physical_start = MEMORY_4G;
                        new.resource_length = entry_top - MEMORY_4G;
                    }
                } else {
                    continue;
                }
            }

            if new.resource_type == RESOURCE_SYSTEM_MEMORY {
                new.resource_type = RESOURCE_MEMORY_UNACCEPTED;
            } else if new.resource_type == RESOURCE_MEMORY_RESERVED {
                new.resource_type = RESOURCE_SYSTEM_MEMORY;
            }
            regions.push(new);
        }

        #[cfg(feature = "tdx")]
        Self::accept_memory_resources(&mut regions);

        regions
    }

    #[cfg(feature = "tdx")]
    /// Build a 2M granularity bitmap for kernel to track the unaccepted memory
    pub fn build_unaccepted_memory_bitmap(&self) -> u64 {
        #[cfg(not(feature = "lazy-accept"))]
        return 0;

        let bitmap = unsafe {
            memslice::get_dynamic_mem_slice_mut(
                memslice::SliceType::UnacceptedMemoryBitmap,
                self.layout.runtime_unaccepted_bitmap_base as usize,
            )
        };

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

        self.layout.runtime_unaccepted_bitmap_base
    }

    #[cfg(feature = "tdx")]
    fn accept_memory_resources(resources: &mut Vec<ResourceDescription>) {
        use td_layout::runtime::TD_PAYLOAD_PARTIAL_ACCEPT_MEMORY_SIZE;
        use td_uefi_pi::pi;

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

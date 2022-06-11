// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use core::mem::size_of;
use td_layout::build_time::{TD_SHIM_FIRMWARE_BASE, TD_SHIM_FIRMWARE_SIZE};
use td_layout::metadata::{TdxMetadata, TDX_METADATA, TDX_METADATA_PTR};
use td_layout::runtime::{
    self, TD_PAYLOAD_BASE, TD_PAYLOAD_EVENT_LOG_SIZE, TD_PAYLOAD_PAGE_TABLE_BASE,
    TD_PAYLOAD_PAGE_TABLE_SIZE, TD_PAYLOAD_SIZE,
};
use td_layout::{RuntimeMemoryLayout, MIN_MEMORY_SIZE};
use td_shim::e820::{E820Entry, E820Type};
use td_uefi_pi::hob;
use td_uefi_pi::pi::hob::{
    Header, ResourceDescription, EFI_RESOURCE_ATTRIBUTE_ENCRYPTED, HOB_TYPE_RESOURCE_DESCRIPTOR,
    RESOURCE_ATTRIBUTE_INITIALIZED, RESOURCE_ATTRIBUTE_PRESENT, RESOURCE_ATTRIBUTE_TESTED,
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

pub type MemoryMap = E820Table;

pub struct Memory<'a> {
    pub layout: RuntimeMemoryLayout,
    pt: OffsetPageTable<'a>,
    memory_map: MemoryMap,
}

impl<'a> Memory<'a> {
    pub fn new(resources: &[ResourceDescription]) -> Option<Self> {
        // Init system memory resources
        Self::init_memory(resources);

        // Init memory map for all of the system memory information
        let memory_map = Self::create_memory_map(resources);

        // Look for the top region with appropriate size above the
        // low memory and below 4G.
        let mut runtime_top = 0;

        for entry in memory_map.as_slice() {
            let entry_top = entry.addr + entry.size;
            if entry_top - MIN_MEMORY_SIZE >= LOW_MEM_TOP
                && entry_top < MEMORY_4G
                && entry.size >= MIN_MEMORY_SIZE
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
            memory_map,
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
        for entry in self.memory_map.as_slice() {
            let entry_top = entry.addr + entry.size;
            if entry.r#type == E820Type::Memory as u32 && entry_top < MEMORY_4G as u64 {
                td_paging::create_mapping(
                    &mut self.pt,
                    PhysAddr::new(entry.addr),
                    VirtAddr::new(entry.addr),
                    td_paging::PAGE_SIZE_4K as u64,
                    entry.size,
                );
            } else {
                td_paging::create_mapping(
                    &mut self.pt,
                    PhysAddr::new(entry.addr),
                    VirtAddr::new(entry.addr),
                    td_paging::PAGE_SIZE_DEFAULT as u64,
                    entry.size,
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
        let mut table = self.memory_map.clone();

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

    fn init_memory(resources: &[ResourceDescription]) {
        #[cfg(feature = "tdx")]
        Self::accept_memory_resources(resources);
    }

    fn create_memory_map(resources: &[ResourceDescription]) -> MemoryMap {
        let mut memory_map = E820Table::new();

        // Save the unaccepted memory into memory map according to the resource
        // descriptors inside HOB.
        for entry in resources {
            let entry_top = entry.physical_start + entry.resource_length;
            if entry.resource_type == RESOURCE_SYSTEM_MEMORY {
                // Filter out the resources cover image space
                // TBD: it should be ensured by VMM that this kind of resources are not reported as system memory
                if entry.physical_start >= TD_SHIM_FIRMWARE_BASE as u64
                    && entry.physical_start < MEMORY_4G
                {
                    if entry_top > MEMORY_4G {
                        memory_map.add_range(E820Type::Memory, MEMORY_4G, entry_top - MEMORY_4G);
                    }
                } else {
                    memory_map.add_range(
                        E820Type::Memory,
                        entry.physical_start,
                        entry.resource_length,
                    );
                }
            }
        }

        #[cfg(feature = "tdx")]
        // Add private memory region specified by metadata into memory map
        get_memory_info_from_metadata(&mut memory_map);

        memory_map
    }

    #[cfg(feature = "tdx")]
    fn accept_memory_resources(resources: &[ResourceDescription]) {
        use td_uefi_pi::pi;

        for r in resources {
            if r.resource_type == pi::hob::RESOURCE_SYSTEM_MEMORY {
                td::accept_memory_resource_range(r.physical_start, r.resource_length);
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

#[cfg(feature = "tdx")]
fn get_memory_info_from_metadata(memory_map: &mut E820Table) {
    for section in TDX_METADATA.sections {
        // Skip the private memory declared in image space
        if section.memory_address >= TD_SHIM_FIRMWARE_BASE as u64
            && section.memory_address <= MEMORY_4G
        {
            continue;
        };

        memory_map.add_range(
            E820Type::Memory,
            section.memory_address,
            section.memory_data_size,
        );
    }

    #[cfg(feature = "boot-kernel")]
    for section in TDX_METADATA.payload_sections {
        memory_map.add_range(
            E820Type::Memory,
            section.memory_address,
            section.memory_data_size,
        );
    }
}

// Save the private memory into memory map according to the metadata

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

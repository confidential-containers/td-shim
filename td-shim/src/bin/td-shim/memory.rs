// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use td_layout::build_time::{TD_SHIM_FIRMWARE_BASE, TD_SHIM_FIRMWARE_SIZE};
use td_layout::runtime::{
    self, TD_PAYLOAD_BASE, TD_PAYLOAD_EVENT_LOG_SIZE, TD_PAYLOAD_PAGE_TABLE_BASE,
    TD_PAYLOAD_PAGE_TABLE_SIZE, TD_PAYLOAD_SIZE,
};
use td_layout::{RuntimeMemoryLayout, MIN_MEMORY_SIZE};
use td_shim::e820::E820Type;
use td_uefi_pi::hob;
use td_uefi_pi::pi::hob::ResourceDescription;
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

pub struct Memory<'a> {
    pub layout: RuntimeMemoryLayout,
    pt: OffsetPageTable<'a>,
    pub regions: Vec<ResourceDescription>,
}

impl<'a> Memory<'a> {
    pub fn new(resources: &[ResourceDescription]) -> Option<Self> {
        let mut regions: Vec<ResourceDescription> = Vec::new();

        // Look for the top region with appropriate size above the
        // low memory and below 4G.
        let mut runtime_top = 0;
        for entry in resources {
            let entry_top = entry.physical_start + entry.resource_length;
            if entry_top - MIN_MEMORY_SIZE >= LOW_MEM_TOP
                && entry_top < MEMORY_4G
                && entry.resource_length >= MIN_MEMORY_SIZE
                && entry_top > runtime_top
            {
                runtime_top = entry_top;
            }

            // Filter out the resources covers image space
            // TBD: it should be ensured by VMM that this kind of resources should be MMIO
            if entry.physical_start >= TD_SHIM_FIRMWARE_BASE as u64
                && entry.physical_start < MEMORY_4G
            {
                if entry_top > MEMORY_4G {
                    let mut new = *entry;
                    new.physical_start = MEMORY_4G;
                    new.resource_length = entry_top - MEMORY_4G;
                    regions.push(new);
                }
            } else {
                regions.push(*entry);
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

    // - Frame size for runtime memory region is 4K bytes since page-table
    //   level protections are used such as no-execute protection.
    // - Frame size for other memory region is 1G bytes.
    pub fn setup_paging(&mut self) {
        // Init frame allocator
        td_paging::init(TD_PAYLOAD_PAGE_TABLE_BASE, TD_PAYLOAD_PAGE_TABLE_SIZE);

        // Create mapping for 0 - base address of runtime layout region
        td_paging::create_mapping(
            &mut self.pt,
            PhysAddr::new(0),
            VirtAddr::new(0),
            td_paging::PAGE_SIZE_DEFAULT as u64,
            self.layout.runtime_memory_bottom,
        )
        .expect("Fail to map 0 to runtime memory bottom");

        // Create mapping for runtime layout region
        td_paging::create_mapping(
            &mut self.pt,
            PhysAddr::new(self.layout.runtime_memory_bottom),
            VirtAddr::new(self.layout.runtime_memory_bottom),
            td_paging::PAGE_SIZE_4K as u64,
            self.layout.runtime_memory_top - self.layout.runtime_memory_bottom,
        )
        .expect("Fail to map runtime memory region");

        // Create mapping from top of runtime layout region to 4G
        td_paging::create_mapping(
            &mut self.pt,
            PhysAddr::new(self.layout.runtime_memory_top),
            VirtAddr::new(self.layout.runtime_memory_top),
            td_paging::PAGE_SIZE_DEFAULT as u64,
            MEMORY_4G - self.layout.runtime_memory_top,
        )
        .expect("Fail to map runtime memory top to 4G");

        // Setup page table only for system memory resources higher than 4G
        for m in &self.regions {
            let r_end = m.physical_start + m.resource_length;
            if r_end < MEMORY_4G as u64 {
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

        // Setup page-table level protection
        // - Enable Non-Excutable for non-code spaces
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

    #[cfg(feature = "tdx")]
    pub fn accept_memory_resources(&self, num_vcpus: u32) {
        use td_uefi_pi::pi;

        for r in &self.regions {
            if r.resource_type == pi::hob::RESOURCE_SYSTEM_MEMORY {
                td::accept_memory_resource_range(num_vcpus, r.physical_start, r.resource_length);
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

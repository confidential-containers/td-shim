// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use r_uefi_pi::pi::fv;
use uefi_pi::pi::fv_lib;

use elf_loader::elf;
use elf_loader::elf64::ProgramHeader;
use pe_loader::pe;
use pe_loader::pe::Section;

use crate::memslice;
use crate::Memory;

const EXTENDED_FUNCTION_INFO: u32 = 0x80000000;
const VIRT_PHYS_MEM_SIZES: u32 = 0x80000008;

pub const SIZE_4KB: u64 = 0x00001000u64;
// pub const SIZE_2MB: u64 = 0x00200000u64;

// pub const LOCAL_APIC_MODE_XAPIC: u64 = 0x1;
// pub const LOCAL_APIC_MODE_X2APIC: u64 = 0x2;

pub fn efi_size_to_page(size: u64) -> u64 {
    (size + SIZE_4KB - 1) / SIZE_4KB
}

pub fn efi_page_to_size(page: u64) -> u64 {
    page * SIZE_4KB
}

pub fn find_and_report_entry_point(
    mem: &mut Memory,
    image_buffer: &[u8],
) -> Option<(u64, u64, u64)> {
    // Safe because we are the only user.
    let loaded_buffer = unsafe { memslice::get_mem_slice_mut(memslice::SliceType::Payload) };
    let loaded_buffer_slice = loaded_buffer.as_ptr() as u64;
    let res = if elf::is_elf(image_buffer) {
        elf::relocate_elf_with_per_program_header(image_buffer, loaded_buffer, |ph| {
            if !ph.is_executable() {
                mem.set_nx_bit(ph.p_vaddr + loaded_buffer_slice, ph.p_filesz);
            }
            if !ph.is_write() {
                log::info!("WP in elf: {:x}\n", ph.p_vaddr + loaded_buffer_slice);
                mem.set_write_protect(ph.p_vaddr + loaded_buffer_slice, ph.p_filesz);
            }
        })?
    } else if pe::is_x86_64_pe(image_buffer) {
        pe::relocate_pe_mem_with_per_sections(image_buffer, loaded_buffer, |sc| {
            if !sc.is_executable() {
                mem.set_nx_bit(
                    sc.section_virtual_address() as u64 + loaded_buffer_slice,
                    sc.section_size() as u64,
                );
            }
            if !sc.is_write() {
                mem.set_write_protect(
                    sc.section_virtual_address() as u64 + loaded_buffer_slice,
                    sc.section_size() as u64,
                );
            }
        })?
    } else {
        return None;
    };
    log::info!(
        "image_entry: {:x}, image_base: {:x}, image_size: {:x}\n",
        res.0,
        res.1,
        res.2
    );
    Some(res)
}

/// CpuGetMemorySpaceSize returns the maximum physical memory addressability of the processor.
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

    // TBD: Currently we only map the 64GB memory, change back to size_of_mem_space once page table
    // allocator can be ready.
    core::cmp::min(36, size_of_mem_space)
}

pub fn get_memory_size(hob: &[u8]) -> u64 {
    let cpu_men_space_size = cpu_get_memory_space_size() as u32;
    let cpu_memory_size = 2u64.pow(cpu_men_space_size);
    let hob_memory_size = uefi_pi::hob_lib::get_total_memory_top(hob).unwrap();
    let mem_size = core::cmp::min(cpu_memory_size, hob_memory_size);
    log::info!("memory_size: 0x{:x}\n", mem_size);
    mem_size
}

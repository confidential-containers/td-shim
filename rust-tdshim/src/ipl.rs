// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use elf_loader::elf;
use elf_loader::elf64::ProgramHeader;
use pe_loader::pe::{self, Section};
use td_layout::memslice;
use td_layout::runtime::{TD_PAYLOAD_BASE, TD_PAYLOAD_SIZE};

use crate::memory::Memory;

const SIZE_4KB: u64 = 0x00001000u64;

pub fn efi_size_to_page(size: u64) -> u64 {
    // It should saturate, but in case...
    size.saturating_add(SIZE_4KB - 1) / SIZE_4KB
}

pub fn efi_page_to_size(page: u64) -> u64 {
    // It should saturate, but in case...
    page.saturating_mul(SIZE_4KB) & !(SIZE_4KB - 1)
}

pub fn find_and_report_entry_point(
    mem: &mut Memory,
    image_buffer: &[u8],
) -> Option<(u64, u64, u64)> {
    // Safe because we are the only user in single-thread context.
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

    let entry = res.0;
    let base = res.1;
    let size = res.2;
    if base < TD_PAYLOAD_BASE as u64
        || base >= TD_PAYLOAD_BASE + TD_PAYLOAD_SIZE as u64
        || size > TD_PAYLOAD_SIZE as u64 - (base - TD_PAYLOAD_BASE)
        || entry < base
        || entry > base + size
    {
        log::error!("invalid payload binary");
        None
    } else {
        log::info!(
            "image_entry: {:x}, image_base: {:x}, image_size: {:x}\n",
            entry,
            base,
            size
        );
        Some(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_to_page() {
        assert_eq!(efi_size_to_page(0), 0);
        assert_eq!(efi_size_to_page(1), 1);
        assert_eq!(efi_size_to_page(SIZE_4KB), 1);
        assert_eq!(efi_size_to_page(SIZE_4KB + 1), 2);
        assert_eq!(efi_size_to_page(u64::MAX), u64::MAX / SIZE_4KB);
        assert_eq!(efi_page_to_size(1), SIZE_4KB);
        assert_eq!(efi_page_to_size(u64::MAX), u64::MAX & !(SIZE_4KB - 1));
    }

    #[test]
    fn test_parse_elf() {
        let elf = include_bytes!("../../data/blobs/td-payload.elf");
        let mut loaded_buffer = vec![0u8; elf.len()];

        assert!(elf::is_elf(elf));
        elf::relocate_elf_with_per_program_header(elf, &mut loaded_buffer, |_ph| {}).unwrap();
    }

    #[test]
    fn test_parse_pe() {
        let efi = include_bytes!("../../data/blobs/td-payload.efi");
        let mut loaded_buffer = vec![0u8; efi.len() * 2];

        assert!(pe::is_x86_64_pe(efi));
        pe::relocate_pe_mem_with_per_sections(efi, &mut loaded_buffer, |_ph| {}).unwrap();
    }
}

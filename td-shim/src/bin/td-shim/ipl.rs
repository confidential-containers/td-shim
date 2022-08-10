// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use td_layout::memslice;
use td_loader::elf;
use td_loader::elf64::ProgramHeader;
use td_loader::pe::{self, Section};

use crate::memory::Memory;

const SIZE_4KB: u64 = 0x00001000u64;

pub enum ExecutablePayloadType {
    Elf,
    PeCoff,
}

pub struct PayloadRelocationInfo {
    pub image_type: ExecutablePayloadType,
    pub base: u64,
    pub size: u64,
    pub entry_point: u64,
}

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
    loaded_buffer: &mut [u8],
) -> Option<PayloadRelocationInfo> {
    let loaded_buffer_slice = loaded_buffer.as_ptr() as u64;
    let image_type;

    let res = if elf::is_elf(image_buffer) {
        image_type = ExecutablePayloadType::Elf;
        elf::relocate_elf_with_per_program_header(image_buffer, loaded_buffer)?
    } else if pe::is_x86_64_pe(image_buffer) {
        image_type = ExecutablePayloadType::PeCoff;
        pe::relocate_pe_mem_with_per_sections(image_buffer, loaded_buffer)?
    } else {
        return None;
    };

    let entry_point = res.0;
    let base = res.1;
    let size = res.2;
    let loaded_buf_base = loaded_buffer.as_ptr() as u64;
    if base < loaded_buf_base
        || base >= loaded_buf_base + loaded_buffer.len() as u64
        || size > loaded_buffer.len() as u64 - (base - loaded_buf_base)
        || entry_point < base
        || entry_point > base + size
    {
        log::error!("invalid payload binary");
        None
    } else {
        log::info!(
            "image_entry: {:x}, image_base: {:x}, image_size: {:x}\n",
            entry_point,
            base,
            size
        );
        Some(PayloadRelocationInfo {
            image_type,
            base,
            size,
            entry_point,
        })
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
        let elf = include_bytes!("../../../../data/blobs/td-payload.elf");
        let mut loaded_buffer = vec![0u8; elf.len()];

        assert!(elf::is_elf(elf));
        elf::relocate_elf_with_per_program_header(elf, &mut loaded_buffer, |_ph| {}).unwrap();
    }

    #[test]
    fn test_parse_pe() {
        let efi = include_bytes!("../../../../data/blobs/td-payload.efi");
        let mut loaded_buffer = vec![0u8; efi.len() * 2];

        assert!(pe::is_x86_64_pe(efi));
        pe::relocate_pe_mem_with_per_sections(efi, &mut loaded_buffer, |_ph| {}).unwrap();
    }
}

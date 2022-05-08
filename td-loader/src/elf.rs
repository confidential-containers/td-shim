// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use scroll::Pwrite;

use crate::elf64::{ProgramHeader, PT_LOAD, PT_PHDR};

use core::ops::Range;

const SIZE_4KB: u64 = 0x00001000u64;

/// Number of bytes in an identifier.
pub const SIZEOF_IDENT: usize = 16;

pub const R_X86_64_RELATIVE: u32 = 8;

pub const ELFMAG: [u8; 4] = [b'\x7F', b'E', b'L', b'F'];

pub fn is_elf(image: &[u8]) -> bool {
    image.len() >= 4 && image[0..4] == ELFMAG
}

pub fn relocate_elf_with_per_program_header(
    image: &[u8],
    loaded_buffer: &mut [u8],
    mut program_header_closures: impl FnMut(ProgramHeader),
) -> Option<(u64, u64, u64)> {
    let new_image_base = loaded_buffer as *const [u8] as *const u8 as usize;
    // parser file and get entry point
    let elf = crate::elf64::Elf::parse(image)?;

    let mut bottom: u64 = 0xFFFFFFFFu64;
    let mut top: u64 = 0u64;

    for ph in elf.program_headers() {
        if ph.p_type == PT_LOAD {
            if bottom > ph.p_vaddr {
                bottom = ph.p_vaddr;
            }
            if top < ph.p_vaddr.checked_add(ph.p_memsz)? {
                top = ph.p_vaddr + ph.p_memsz;
            }
        }
    }

    bottom.checked_add(new_image_base as u64)?;
    top.checked_add(new_image_base as u64)?;
    let mut bottom = bottom + new_image_base as u64;
    let mut top = top + new_image_base as u64;
    bottom = align_value(bottom, SIZE_4KB, true);
    top = align_value(top, SIZE_4KB, false);
    top.checked_sub(bottom)?;
    // load per program header
    for ph in elf.program_headers() {
        if (ph.p_type == PT_LOAD || ph.p_type == PT_PHDR) && ph.p_memsz != 0 {
            if ph.p_offset.checked_add(ph.p_filesz)? > image.len() as u64
                || ph.p_vaddr.checked_add(ph.p_filesz)? > loaded_buffer.len() as u64
            {
                return None;
            }
            let data_range = ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize;
            let loaded_range = (ph.p_vaddr) as usize..(ph.p_vaddr + ph.p_filesz) as usize;
            loaded_buffer[loaded_range].copy_from_slice(&image[data_range]);
        }
    }

    // relocate to base
    for reloc in elf.relocations()? {
        if reloc.r_type() == R_X86_64_RELATIVE {
            let r_addend = reloc.r_addend;
            loaded_buffer
                .pwrite::<u64>(
                    new_image_base.checked_add(r_addend as usize)? as u64,
                    reloc.r_offset as usize,
                )
                .ok()?;
        }
    }

    for ph in elf.program_headers() {
        program_header_closures(ph);
    }

    Some((
        elf.header.e_entry.checked_add(new_image_base as u64)? as u64,
        bottom as u64,
        (top - bottom) as u64,
    ))
}

pub fn parse_init_array_section(image: &[u8]) -> Option<Range<usize>> {
    // parser file and get the .init_array section, if any
    let elf = crate::elf64::Elf::parse(image)?;

    for sh in elf.section_headers() {
        if sh.sh_type == crate::elf64::SHT_INIT_ARRAY {
            sh.sh_addr.checked_add(sh.sh_size)?;
            return Some(sh.vm_range());
        }
    }
    None
}

pub fn parse_finit_array_section(image: &[u8]) -> Option<Range<usize>> {
    // parser file and get the .finit_array section, if any
    let elf = crate::elf64::Elf::parse(image)?;

    for sh in elf.section_headers() {
        if sh.sh_type == crate::elf64::SHT_FINI_ARRAY {
            sh.sh_addr.checked_add(sh.sh_size)?;
            return Some(sh.vm_range());
        }
    }
    None
}

/// flag true align to low address else high address
fn align_value(value: u64, align: u64, flag: bool) -> u64 {
    if flag {
        value & ((!(align - 1)) as u64)
    } else {
        value - (value & (align - 1)) as u64 + align
    }
}

#[cfg(test)]
mod test_elf_loader {
    use std::vec;

    #[test]
    fn test_is_elf() {
        let image_bytes = include_bytes!("../../data/blobs/td-payload.elf");

        assert_eq!(super::is_elf(image_bytes), true);
    }
    #[test]
    fn test_relocate() {
        let pe_image = &include_bytes!("../../data/blobs/td-payload.elf")[..];

        let mut loaded_buffer = vec![0u8; 0x800000];

        super::relocate_elf_with_per_program_header(pe_image, loaded_buffer.as_mut_slice(), |_| ());
    }
}

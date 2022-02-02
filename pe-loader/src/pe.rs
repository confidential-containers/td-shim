// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Portable Executable File Format Parser
//!
//! Quotation from [Portable Executable](https://en.wikipedia.org/wiki/Portable_Executable)
//!
//! The Portable Executable (PE) format is a file format for executables, object code, DLLs and
//! others used in 32-bit and 64-bit versions of Windows operating systems. The PE format is a data
//! structure that encapsulates the information necessary for the Windows OS loader to manage the
//! wrapped executable code. This includes dynamic library references for linking, API export and
//! import tables, resource management data and thread-local storage (TLS) data. On NT operating
//! systems, the PE format is used for EXE, DLL, SYS (device driver), MUI and other file types.
//!
//! The Unified Extensible Firmware Interface (UEFI) specification states that PE is the standard
//! executable format in EFI environments.
//!
//! For the Portable Executable File Format, please refer to
//! [Structure of a Portable Executable 32 bit](https://en.wikipedia.org/wiki/Portable_Executable#/media/File:Portable_Executable_32_bit_Structure_in_SVG_fixed.svg)
//!
//! ### Relocations
//!
//! PE files normally do not contain position-independent code. Instead they are compiled to a
//! preferred base address, and all addresses emitted by the compiler/linker are fixed ahead of time.
//! If a PE file cannot be loaded at its preferred address (because it's already taken by something
//! else), the operating system will rebase it. This involves recalculating every absolute address
//! and modifying the code to use the new values. The loader does this by comparing the preferred
//! and actual load addresses, and calculating a delta value. This is then added to the preferred
//! address to come up with the new address of the memory location. Base relocations are stored in
//! a list and added, as needed, to an existing memory location. The resulting code is now private
//! to the process and no longer shareable, so many of the memory saving benefits of DLLs are lost
//! in this scenario. It also slows down loading of the module significantly. For this reason
//! rebasing is to be avoided wherever possible, and the DLLs shipped by Microsoft have base
//! addresses pre-computed so as not to overlap. In the no rebase case PE therefore has the
//! advantage of very efficient code, but in the presence of rebasing the memory usage hit can be
//! expensive. This contrasts with ELF which uses fully position-independent code and a global
//! offset table, which trades off execution time in favor of lower memory usage.
//!
//! ### PE32+ Image File Format
//!
//! The image file format for the x64 platform is known as PE32+. As one would expect, the file
//! format is derived from the PE file format with only very slight modifications. For instance,
//! 64-bit binaries contain an IMAGE_OPTIONAL_HEADER64 rather than an IMAGE_OPTIONAL_HEADER.
//! The differences between these two structures are described as below:
//! - Field `BaseOfData` has been removed
//! - Field `ImageBase`, `SizeOfStackReserve`, `SizeOfStackCommit`, `SizeOfHeapReserve` and
//!   `SizeOfHeapCommit` have been changed to 64-bit.
//!
//! In general, any structure attribute in the PE image that made reference to a 32-bit virtual
//! address directly rather than through an RVA (Relative Virtual Address) has been expanded to
//! a 64-bit attribute in PE32+. Other examples of this include the IMAGE_TLS_DIRECTORY structure
//! and the IMAGE_LOAD_CONFIG_DIRECTORY structure.
//!
//! With the exception of certain field offsets in specific structures, the PE32+ image file format
//! is largely backward compatible with PE both in use and in form.

use scroll::{Pread, Pwrite};

/// The section contains executable code.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// The section can be executed as code.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// The section can be written to.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const PE_SIGNATURE: u32 = 0x00004550;
const DOS_SIGNATURE: u16 = 0x5a4d;
const MACHINE_X64: u16 = 0x8664;
const OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const REL_BASED_DIR64: u8 = 10;

// DOS header is 64 bytes.
const DOS_HEADER_SIZE: usize = 0x40;
// COFF header is 24 bytes.
const COFF_HEADER_SIZE: usize = 24;
// COFF Standard Fields for PE+ is 24 bytes, instead of 28 bytes for PE.
const COFF_STANDAND_SIZE: usize = 24;
// COFF Optional Fields for PE+ is 88 bytes, instead of 68 bytes for PE.
const COFF_OPTIONAL_SIZE: usize = 88;
// COFF Section is 40 bytes
const COFF_SECTION_SIZE: usize = 40;

/// Check whether the data s a file header of `Portable Executable` format.
pub fn is_x86_64_pe(pe_image: &[u8]) -> bool {
    // Limit the image file size to below 2GB, that should be well enough.
    if pe_image.len() <= DOS_HEADER_SIZE || pe_image.len() > i32::MAX as usize {
        return false;
    }
    if pe_image.pread::<u16>(0).unwrap_or_default() != DOS_SIGNATURE {
        return false;
    }

    let coff_header_offset = pe_image
        .pread::<u32>(0x3c)
        .map(|v| v as usize)
        .unwrap_or_else(|_| pe_image.len());
    if pe_image.len() <= coff_header_offset + COFF_HEADER_SIZE {
        return false;
    }

    let coff_region = &pe_image[coff_header_offset..coff_header_offset + COFF_HEADER_SIZE];
    if coff_region.pread::<u32>(0).unwrap_or_default() != PE_SIGNATURE {
        return false;
    }

    // if pe is x64
    if coff_region.pread::<u16>(4).unwrap_or_default() != MACHINE_X64 {
        return false;
    }

    true
}

/// Relocate a `Portable Executable` object to the new base.
pub fn relocate(pe_image: &[u8], new_pe_image: &mut [u8], new_image_base: usize) -> Option<usize> {
    relocate_with_per_section(pe_image, new_pe_image, new_image_base, |_| ())
}

/// Relocate a `Portable Executable` object, using address of `new_pe_image' as new base.
pub fn relocate_pe_mem_with_per_sections(
    pe_image: &[u8],
    new_pe_image: &mut [u8],
    section_callback: impl FnMut(Section),
) -> Option<(u64, u64, u64)> {
    let image_size = pe_image.len();
    let new_image_base = new_pe_image as *const [u8] as *const u8 as usize;
    let res = relocate_with_per_section(pe_image, new_pe_image, new_image_base, section_callback)?;

    Some((res as u64, new_image_base as u64, image_size as u64))
}

/// Relocate a `Portable Executable` object to the new base, and invoke the callback for each
/// section.
pub fn relocate_with_per_section(
    pe_image: &[u8],
    new_pe_image: &mut [u8],
    new_image_base: usize,
    mut section_closures: impl FnMut(Section),
) -> Option<usize> {
    log::info!("start relocate...");
    let image_buffer = pe_image;
    let loaded_buffer = new_pe_image;

    // Validate and parse Coff Header.
    if image_buffer.len() < DOS_HEADER_SIZE {
        return None;
    }
    let coff_header_offset = image_buffer.pread::<u32>(0x3c).ok()? as usize;
    if coff_header_offset < DOS_HEADER_SIZE {
        return None;
    }
    let coff_header_end = coff_header_offset.checked_add(COFF_HEADER_SIZE)?;
    image_buffer.len().checked_sub(coff_header_end)?;
    let coff_header_region = &image_buffer[coff_header_offset..coff_header_end];
    let num_sections = coff_header_region.pread::<u16>(6).ok()? as usize;
    let coff_optional_size = coff_header_region.pread::<u16>(20).ok()? as usize;
    if coff_optional_size < COFF_OPTIONAL_SIZE {
        return None;
    }

    // Validate and parse COFF Standard Fields.
    let coff_standard_offset = coff_header_end;
    let coff_standard_end = coff_standard_offset.checked_add(COFF_STANDAND_SIZE)?;
    image_buffer.len().checked_sub(coff_standard_end)?;
    let coff_standard_region = &image_buffer[coff_standard_offset..coff_standard_end];
    if coff_standard_region.pread::<u16>(0).ok()? != OPTIONAL_HDR64_MAGIC {
        return None;
    }
    let entry_point = coff_standard_region.pread::<u32>(16).ok()?;

    // Validate and parse COFF Optional Fields.
    // Validate optional header and read data from it.
    let coff_optional_offset = coff_standard_end;
    let coff_optional_end = coff_header_end.checked_add(coff_optional_size)?;
    image_buffer.len().checked_sub(coff_optional_end)?;
    let coff_optional_region = &image_buffer[coff_optional_offset..coff_optional_end];
    let image_base = coff_optional_region.pread::<u64>(0).ok()?;

    // Validate section header region
    // There's no "Data Directories", so "Section Table" follows COFF Optional Fields.
    let section_offset = coff_optional_end;
    let section_size = num_sections.checked_mul(COFF_SECTION_SIZE)?;
    let section_end = section_offset.checked_add(section_size)?;
    let total_header_size = section_end;
    image_buffer.len().checked_sub(total_header_size)?;
    loaded_buffer.len().checked_sub(total_header_size)?;
    let sections_buffer = &image_buffer[section_offset..section_end];

    // Copy all headers and update entrypoint.
    loaded_buffer[0..total_header_size].copy_from_slice(&image_buffer[0..total_header_size]);
    loaded_buffer
        .pwrite(new_image_base as u64, coff_optional_offset)
        .ok()?;

    let sections = Sections::parse(sections_buffer, num_sections as usize)?;
    // Load the PE header into the destination memory
    for section in sections {
        let section_size = section.section_size() as usize;
        let src_start = section.pointer_to_raw_data as usize;
        let src_end = src_start.checked_add(section_size)?;
        let dst_start = section.virtual_address as usize;
        let dst_end = dst_start.checked_add(section_size)?;

        image_buffer.len().checked_sub(src_end as usize)?;
        loaded_buffer.len().checked_sub(dst_end as usize)?;
        loaded_buffer[dst_start..dst_end].copy_from_slice(&image_buffer[src_start..src_end]);
        if section.virtual_size as usize > section_size {
            let fill_end = dst_start.checked_add(section.virtual_size as usize)?;
            loaded_buffer[dst_end..fill_end].fill(0);
        }
    }

    let sections = Sections::parse(sections_buffer, num_sections as usize)?;
    for section in sections {
        if &section.name[0..6] == b".reloc" {
            reloc_to_base(
                loaded_buffer,
                image_buffer,
                &section,
                image_base as usize,
                new_image_base as usize,
            )?;
        }
    }

    let sections = Sections::parse(sections_buffer, num_sections as usize)?;
    for section in sections {
        section_closures(section);
    }

    Some(new_image_base + entry_point as usize)
}

#[repr(C, align(4))]
#[derive(Default, Pread, Pwrite)]
pub struct Section {
    name: [u8; 8],                //8
    virtual_size: u32,            //4
    virtual_address: u32,         //4
    size_of_raw_data: u32,        //4
    pointer_to_raw_data: u32,     //4
    pointer_to_relocations: u32,  //4
    pointer_to_line_numbers: u32, //4
    number_of_relocations: u16,   //2
    number_of_line_numbers: u16,  //2
    characteristics: u32,         //4
}

impl core::fmt::Debug for Section {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = self.name;
        f.debug_struct("Section")
            .field(
                "name",
                &format_args!(
                    "{}{}{}{}{}{}{}{}",
                    name[0] as char,
                    name[1] as char,
                    name[2] as char,
                    name[3] as char,
                    name[4] as char,
                    name[5] as char,
                    name[6] as char,
                    name[7] as char
                ),
            )
            .field("virtual_size", &format_args!("{:x}", self.virtual_size))
            .field(
                "virtual_address",
                &format_args!("{:x}", self.virtual_address),
            )
            .field(
                "size_of_raw_data",
                &format_args!("{:x}", self.size_of_raw_data),
            )
            .field(
                "pointer_to_raw_data",
                &format_args!("{:x}", self.pointer_to_raw_data),
            )
            .field(
                "pointer_to_relocations",
                &format_args!("{:x}", self.pointer_to_relocations),
            )
            .field(
                "pointer_to_line_numbers",
                &format_args!("{:x}", self.pointer_to_line_numbers),
            )
            .field(
                "number_of_relocations",
                &format_args!("{:x}", self.number_of_relocations),
            )
            .field(
                "number_of_line_numbers",
                &format_args!("{:x}", self.number_of_line_numbers),
            )
            .field(
                "characteristics",
                &format_args!("{:x}", self.characteristics),
            )
            .finish()
    }
}

impl Section {
    pub fn is_executable(&self) -> bool {
        self.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0
    }

    pub fn is_write(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    pub fn section_virtual_address(&self) -> u32 {
        self.virtual_address
    }

    pub fn section_size(&self) -> u32 {
        core::cmp::min(self.size_of_raw_data, self.virtual_size)
    }
}

pub struct Sections<'a> {
    index: usize,
    entries: &'a [u8],
    num_sections: usize,
}

impl<'a> Sections<'a> {
    // section entries byties, num_sections: total sections
    pub fn parse(entries: &'a [u8], num_sections: usize) -> Option<Self> {
        let sz = num_sections.checked_mul(COFF_SECTION_SIZE)?;
        if entries.len() < sz {
            None
        } else {
            Some(Sections {
                index: 0,
                entries,
                num_sections,
            })
        }
    }
}

impl<'a> Iterator for Sections<'a> {
    type Item = Section;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.num_sections {
            return None;
        }

        let offset = self.index * COFF_SECTION_SIZE;
        let current_bytes = &self.entries[offset..];
        let section: Section = current_bytes.pread(0).ok()?;
        self.index += 1;
        Some(section)
    }
}

#[derive(Clone, Copy)]
pub struct RelocationEntry {
    pub entry_type: u8,
    pub offset: u32,
}

pub struct RelocationEntries<'a> {
    index: usize,
    max_index: usize,
    entries: &'a [u8],
}

impl<'a> RelocationEntries<'a> {
    const ENTRY_SIZE: usize = core::mem::size_of::<u16>();

    pub fn parse(entries: &'a [u8]) -> Option<Self> {
        Some(RelocationEntries {
            index: 0,
            max_index: entries.len() / Self::ENTRY_SIZE,
            entries,
        })
    }
}

impl<'a> Iterator for RelocationEntries<'a> {
    type Item = RelocationEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.max_index {
            return None;
        }

        let entry: u16 = self.entries.pread(self.index * Self::ENTRY_SIZE).ok()?;
        self.index += 1;
        Some(RelocationEntry {
            entry_type: (entry >> 12) as u8,
            offset: (entry & 0xfff) as u32,
        })
    }
}

pub struct Relocations<'a> {
    offset: usize,
    relocations: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct Relocation<'a> {
    pub page_rva: u32,
    pub block_size: u32,
    pub entries: &'a [u8],
}

impl<'a> Relocations<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        Some(Relocations {
            offset: 0,
            relocations: bytes,
        })
    }
}

impl<'a> Iterator for Relocations<'a> {
    type Item = Relocation<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset > self.relocations.len().checked_sub(8)? {
            return None;
        }

        let bytes = &self.relocations[self.offset..];
        let page_rva = bytes.pread(0).ok()?;
        let block_size: u32 = bytes.pread(core::mem::size_of::<u32>()).ok()?;
        block_size.checked_sub((core::mem::size_of::<u32>() * 2) as u32)?;
        bytes.len().checked_sub(block_size as usize)?;
        self.offset += block_size as usize;

        let entries = &bytes[(core::mem::size_of::<u32>() * 2) as usize..block_size as usize];
        Some(Relocation {
            page_rva,
            block_size,
            entries,
        })
    }
}

fn reloc_to_base(
    loaded_buffer: &mut [u8],
    image_buffer: &[u8],
    section: &Section,
    image_base: usize,
    new_image_base: usize,
) -> Option<()> {
    let section_size = section.section_size();
    let relocation_range_in_image =
        section.pointer_to_raw_data as usize..(section.pointer_to_raw_data + section_size) as usize;
    let relocations = Relocations::parse(&image_buffer[relocation_range_in_image])?;

    for relocation in relocations {
        for entry in RelocationEntries::parse(relocation.entries)? {
            match entry.entry_type {
                REL_BASED_DIR64 => {
                    let location = (relocation.page_rva.checked_add(entry.offset)?) as usize;
                    let value: u64 = loaded_buffer.pread(location).ok()?;
                    value
                        .checked_sub(image_base as u64)?
                        .checked_add(new_image_base as u64)?;
                    loaded_buffer
                        .pwrite(
                            value - image_base as u64 + new_image_base as u64,
                            location as usize,
                        )
                        .ok()?;
                    log::trace!(
                        "reloc {:08x}:  {:012x} -> {:012x}",
                        location,
                        value,
                        value - image_base as u64 + new_image_base as u64
                    );
                }
                _ => continue,
            }
        }
    }

    Some(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::vec;

    #[test]
    fn test_is_pe() {
        let image_bytes = include_bytes!("../../data/blobs/td-payload.efi");
        let mut status = is_x86_64_pe(image_bytes);
        assert_eq!(status, true);

        let image_bytes = &mut [0u8; 10][..];
        status = is_x86_64_pe(image_bytes);
        assert_eq!(status, false);

        let image_bytes = &mut [0u8; 0x55][..];
        status = is_x86_64_pe(image_bytes);
        assert_eq!(status, false);

        image_bytes[0] = 0x4du8;
        image_bytes[1] = 0x5au8;
        status = is_x86_64_pe(image_bytes);
        assert_eq!(status, false);

        image_bytes[0x3c] = 0x10;
        image_bytes[0x10] = 0x50;
        image_bytes[0x11] = 0x45;
        image_bytes[0x12] = 0x00;
        image_bytes[0x13] = 0x00;
        status = is_x86_64_pe(image_bytes);
        assert_eq!(status, false);

        image_bytes[0x3c] = 0xAA;
        status = is_x86_64_pe(image_bytes);
        assert_eq!(status, false);
    }

    #[test]
    fn test_sections() {
        use scroll::Pread;
        let pe_image = &include_bytes!("../../data/blobs/td-payload.efi")[..];

        let coff_header_offset = pe_image.pread::<u32>(0x3c).unwrap() as usize;
        let pe_region = &pe_image[coff_header_offset..];

        let num_sections = pe_region.pread::<u16>(6).unwrap() as usize;
        let optional_header_size = pe_region.pread::<u16>(20).unwrap() as usize;
        let optional_region = &pe_image[24 + coff_header_offset..];

        // check optional_hdr64_magic
        assert_eq!(
            optional_region.pread::<u16>(0).unwrap(),
            OPTIONAL_HDR64_MAGIC
        );

        let total_header_size =
            (24 + coff_header_offset + optional_header_size + num_sections * 40) as usize;
        let entry_point = optional_region.pread::<u32>(16).unwrap();
        let image_base = optional_region.pread::<u64>(24).unwrap();
        assert_eq!(total_header_size, 584);
        assert_eq!(image_base, 0x1_4000_0000);
        assert_eq!(entry_point, 0x1040);

        let mut num_section = 0;
        let sections_buffer = &pe_image[(24 + coff_header_offset + optional_header_size)..];
        let sections = Sections::parse(sections_buffer, num_sections as usize).unwrap();
        for section in sections {
            num_section += 1;
            println!("{:?}", section)
        }
        assert_eq!(num_section, 5);
    }

    #[test]
    fn test_relocate_pe_mem_with_per_sections() {
        use env_logger::Env;
        let env = Env::default()
            .filter_or("MY_LOG_LEVEL", "trace")
            .write_style_or("MY_LOG_STYLE", "always");
        env_logger::init_from_env(env);

        let pe_image = &include_bytes!("../../data/blobs/td-payload.efi")[..];
        let mut loaded_buffer = vec![0u8; 0x200000];

        let mut entries = 0;
        if let Some((image_entry, image_base, image_size)) =
            relocate_pe_mem_with_per_sections(pe_image, loaded_buffer.as_mut_slice(), |_| ())
        {
            println!(
                " 0x:{:x}\n 0x:{:x}\n 0x:{:x}\n",
                image_entry, image_base, image_size
            );
            assert_eq!(image_entry, loaded_buffer.as_ptr() as usize as u64 + 0x1040);
            assert_eq!(image_base, loaded_buffer.as_ptr() as usize as u64);
            assert_eq!(image_size, 0x27400);
            entries += 1;
        }
        assert_eq!(entries, 1);
    }
}

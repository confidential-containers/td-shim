// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

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

pub fn is_pe(pe_image: &[u8]) -> bool {
    if pe_image.len() <= 0x42 {
        return false;
    }
    if pe_image.pread::<u16>(0).unwrap() != DOS_SIGNATURE {
        return false;
    }
    let pe_header_offset = pe_image.pread::<u32>(0x3c).unwrap() as usize;

    if pe_image.len() <= pe_header_offset + 6 {
        return false;
    }

    let pe_region = &pe_image[pe_header_offset..];

    if pe_region.pread::<u32>(0).unwrap() != PE_SIGNATURE {
        return false;
    }
    // if pe is x64
    if pe_region.pread::<u16>(4).unwrap() != MACHINE_X64 {
        return false;
    }
    true
}

pub fn relocate(pe_image: &[u8], new_pe_image: &mut [u8], new_image_base: usize) -> Option<usize> {
    relocate_with_per_section(pe_image, new_pe_image, new_image_base, |_| ())
}

pub fn relocate_pe_mem_with_per_sections(
    image: &[u8],
    loaded_buffer: &mut [u8],
    section_closures: impl FnMut(Section),
) -> Option<(u64, u64, u64)> {
    // parser file and get entry point
    let image_buffer = image;
    let image_size = image.len();
    let new_image_base = loaded_buffer as *const [u8] as *const u8 as usize;

    let res = relocate_with_per_section(
        image_buffer,
        loaded_buffer,
        new_image_base,
        section_closures,
    )?;

    Some((
        res as u64,
        new_image_base as usize as u64,
        image_size as u64,
    ))
}

pub fn relocate_with_per_section(
    pe_image: &[u8],
    new_pe_image: &mut [u8],
    new_image_base: usize,
    mut section_closures: impl FnMut(Section),
) -> Option<usize> {
    log::info!("start relocate...");
    let image_buffer = pe_image;
    let loaded_buffer = new_pe_image;

    let pe_header_offset = pe_image.pread::<u32>(0x3c).ok()? as usize;

    pe_image.len().checked_sub(pe_header_offset)?;
    image_buffer.len().checked_sub(24 + pe_header_offset)?;

    let pe_region = &pe_image[pe_header_offset..];

    let num_sections = pe_region.pread::<u16>(6).ok()? as usize;
    let optional_header_size = pe_region.pread::<u16>(20).ok()? as usize;
    let optional_region = &image_buffer[24 + pe_header_offset..];

    // check optional_hdr64_magic
    if optional_region.pread::<u16>(0).ok()? != OPTIONAL_HDR64_MAGIC {
        return None;
    }

    let entry_point = optional_region.pread::<u32>(16).ok()?;
    let image_base = optional_region.pread::<u64>(24).ok()?;
    image_buffer
        .len()
        .checked_sub(24 + pe_header_offset + optional_header_size)?;
    let sections_buffer = &image_buffer[(24 + pe_header_offset + optional_header_size)..];

    let total_header_size =
        (24 + pe_header_offset + optional_header_size + num_sections * 40) as usize;
    loaded_buffer.len().checked_sub(total_header_size)?;
    image_buffer.len().checked_sub(total_header_size)?;
    loaded_buffer[0..total_header_size].copy_from_slice(&image_buffer[0..total_header_size]);
    let _ = loaded_buffer.pwrite(new_image_base as u64, (24 + pe_header_offset + 24) as usize);

    let sections = Sections::parse(sections_buffer, num_sections as usize)?;
    // Load the PE header into the destination memory
    for section in sections {
        let section_size = core::cmp::min(section.size_of_raw_data, section.virtual_size);
        image_buffer
            .len()
            .checked_sub(section.pointer_to_raw_data.checked_add(section_size)? as usize)?;
        section.virtual_address.checked_add(section_size)?;
        loaded_buffer
            .len()
            .checked_sub((section.virtual_address + section_size) as usize)?;
        let section_range =
            section.virtual_address as usize..(section.virtual_address + section_size) as usize;
        loaded_buffer[section_range.clone()].fill(0);
        loaded_buffer[section_range.clone()].copy_from_slice(
            &image_buffer[section.pointer_to_raw_data as usize
                ..(section.pointer_to_raw_data + section_size) as usize],
        );
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
        Some(Sections {
            index: 0,
            entries,
            num_sections,
        })
    }
}

impl<'a> Iterator for Sections<'a> {
    type Item = Section;
    fn next(&mut self) -> Option<Self::Item> {
        const ENTRY_SIZE: usize = 40;
        if self.index == self.num_sections {
            return None;
        }
        let offset = self.index * ENTRY_SIZE;

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
    entries: &'a [u8],
}

impl<'a> RelocationEntries<'a> {
    pub fn parse(entries: &'a [u8]) -> Option<Self> {
        Some(RelocationEntries { index: 0, entries })
    }
}

impl<'a> Iterator for RelocationEntries<'a> {
    type Item = RelocationEntry;
    fn next(&mut self) -> Option<Self::Item> {
        const ENTRY_SIZE: usize = 2;
        if self.index.checked_mul(core::mem::size_of::<u16>())?
            > self.entries.len().checked_sub(ENTRY_SIZE)?
        {
            return None;
        }

        let entry: u16 = self.entries.pread(self.index * ENTRY_SIZE).ok()?;
        let entry_type = (entry >> 12) as u8;
        let entry_offset = (entry & 0xfff) as u32;

        let res = RelocationEntry {
            entry_type,
            offset: entry_offset,
        };
        self.index += 1;
        Some(res)
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
        bytes.len().checked_sub(block_size as usize)?;
        block_size.checked_sub((core::mem::size_of::<u32>() * 2) as u32)?;
        let entries = &bytes[(core::mem::size_of::<u32>() * 2) as usize..block_size as usize];
        let res = Relocation {
            page_rva,
            block_size,
            entries,
        };
        self.offset += block_size as usize;
        Some(res)
    }
}

fn reloc_to_base(
    loaded_buffer: &mut [u8],
    image_buffer: &[u8],
    section: &Section,
    image_base: usize,
    new_image_base: usize,
) -> Option<()> {
    let section_size = core::cmp::min(section.size_of_raw_data, section.virtual_size);

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
                    let _ = loaded_buffer.pwrite(
                        value - image_base as u64 + new_image_base as u64,
                        location as usize,
                    );
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
        let image_bytes =
            include_bytes!("../../target/x86_64-unknown-uefi/release/rust-tdshim.efi");
        let mut status = is_pe(image_bytes);
        assert_eq!(status, true);

        let image_bytes = &mut [0u8; 10][..];
        status = is_pe(image_bytes);
        assert_eq!(status, false);

        let image_bytes = &mut [0u8; 0x55][..];
        status = is_pe(image_bytes);
        assert_eq!(status, false);

        image_bytes[0] = 0x4du8;
        image_bytes[1] = 0x5au8;
        status = is_pe(image_bytes);
        assert_eq!(status, false);

        image_bytes[0x3c] = 0x10;
        image_bytes[0x10] = 0x50;
        image_bytes[0x11] = 0x45;
        image_bytes[0x12] = 0x00;
        image_bytes[0x13] = 0x00;
        status = is_pe(image_bytes);
        assert_eq!(status, false);

        image_bytes[0x3c] = 0xAA;
        status = is_pe(image_bytes);
        assert_eq!(status, false);
    }
    #[test]
    fn test_sections() {
        use scroll::Pread;
        let pe_image =
            &include_bytes!("../../target/x86_64-unknown-uefi/release/rust-tdshim.efi")[..];

        let pe_header_offset = pe_image.pread::<u32>(0x3c).unwrap() as usize;
        let pe_region = &pe_image[pe_header_offset..];

        let num_sections = pe_region.pread::<u16>(6).unwrap() as usize;
        let optional_header_size = pe_region.pread::<u16>(20).unwrap() as usize;
        let optional_region = &pe_image[24 + pe_header_offset..];

        // check optional_hdr64_magic
        assert_eq!(
            optional_region.pread::<u16>(0).unwrap(),
            super::OPTIONAL_HDR64_MAGIC
        );

        let entry_point = optional_region.pread::<u32>(16).unwrap();
        let image_base = optional_region.pread::<u64>(24).unwrap();

        let sections_buffer = &pe_image[(24 + pe_header_offset + optional_header_size)..];

        let _total_header_size =
            (24 + pe_header_offset + optional_header_size + num_sections * 40) as usize;

        let sections = super::Sections::parse(sections_buffer, num_sections as usize).unwrap();
        println!("entry_point: {:x}", entry_point);
        println!("image_base: {:x}", image_base);
        for section in sections {
            println!("{:?}", section)
        }
        println!("entry: {:x?}", &pe_image[0xf8e0..0xf9e0])
    }

    #[test]
    fn test_relocate_pe_mem_with_per_sections() {
        use env_logger::Env;
        let env = Env::default()
            .filter_or("MY_LOG_LEVEL", "trace")
            .write_style_or("MY_LOG_STYLE", "always");

        env_logger::init_from_env(env);

        let pe_image =
            &include_bytes!("../../target/x86_64-unknown-uefi/release//rust-tdshim.efi")[..];

        let mut loaded_buffer = vec![0u8; 0x200000];

        if let Some((image_entry, image_base, image_size)) =
            super::relocate_pe_mem_with_per_sections(pe_image, loaded_buffer.as_mut_slice(), |_| ())
        {
            println!(
                " 0x:{:x}\n 0x:{:x}\n 0x:{:x}\n",
                image_entry, image_base, image_size
            );
        }
    }
}

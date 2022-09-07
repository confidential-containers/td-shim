// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{fmt, ops::Range};

use scroll::Pread;

/// No file type.
pub const ET_NONE: u16 = 0;
/// Relocatable file.
pub const ET_REL: u16 = 1;
/// Executable file.
pub const ET_EXEC: u16 = 2;
/// Shared object file.
pub const ET_DYN: u16 = 3;
/// Core file.
pub const ET_CORE: u16 = 4;
/// Number of defined types.
pub const ET_NUM: u16 = 5;

/// Program header table entry unused
pub const PT_NULL: u32 = 0;
/// Loadable program segment
pub const PT_LOAD: u32 = 1;
/// Dynamic linking information
pub const PT_DYNAMIC: u32 = 2;
/// Program interpreter
pub const PT_INTERP: u32 = 3;
/// Auxiliary information
pub const PT_NOTE: u32 = 4;
/// Reserved
pub const PT_SHLIB: u32 = 5;
/// Entry for header table itself
pub const PT_PHDR: u32 = 6;
/// Thread-local storage segment
pub const PT_TLS: u32 = 7;
/// Number of defined types
pub const PT_NUM: u32 = 8;
/// Start of OS-specific
pub const PT_LOOS: u32 = 0x6000_0000;
/// GCC .eh_frame_hdr segment
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
/// Indicates stack executability
pub const PT_GNU_STACK: u32 = 0x6474_e551;
/// Read-only after relocation
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
/// Sun Specific segment
// pub const PT_LOSUNW: u32 = 0x6fff_fffa;
/// Sun Specific segment
pub const PT_SUNWBSS: u32 = 0x6fff_fffa;
/// Stack segment
pub const PT_SUNWSTACK: u32 = 0x6fff_fffb;
/// End of OS-specific
// pub const PT_HISUNW: u32 = 0x6fff_ffff;
/// End of OS-specific
pub const PT_HIOS: u32 = 0x6fff_ffff;
/// Start of processor-specific
pub const PT_LOPROC: u32 = 0x7000_0000;
/// ARM unwind segment
pub const PT_ARM_EXIDX: u32 = 0x7000_0001;
/// End of processor-specific
pub const PT_HIPROC: u32 = 0x7fff_ffff;
/// Segment is executable
pub const PF_X: u32 = 1;
/// Segment is writable
pub const PF_W: u32 = 1 << 1;

/// Section header table entry unused.
pub const SHT_NULL: u32 = 0;
/// Program data.
pub const SHT_PROGBITS: u32 = 1;
/// Symbol table.
pub const SHT_SYMTAB: u32 = 2;
/// String table.
pub const SHT_STRTAB: u32 = 3;
/// Relocation entries with addends.
pub const SHT_RELA: u32 = 4;
/// Symbol hash table.
pub const SHT_HASH: u32 = 5;
/// Dynamic linking information.
pub const SHT_DYNAMIC: u32 = 6;
/// Notes.
pub const SHT_NOTE: u32 = 7;
/// Program space with no data (bss).
pub const SHT_NOBITS: u32 = 8;
/// Relocation entries, no addends.
pub const SHT_REL: u32 = 9;
/// Reserved.
pub const SHT_SHLIB: u32 = 10;
/// Dynamic linker symbol table.
pub const SHT_DYNSYM: u32 = 11;
/// Array of constructors.
pub const SHT_INIT_ARRAY: u32 = 14;
/// Array of destructors.
pub const SHT_FINI_ARRAY: u32 = 15;
/// Array of pre-constructors.
pub const SHT_PREINIT_ARRAY: u32 = 16;
/// Section group.
pub const SHT_GROUP: u32 = 17;
/// Extended section indeces.
pub const SHT_SYMTAB_SHNDX: u32 = 18;
/// Number of defined types.
pub const SHT_NUM: u32 = 19;
/// Start OS-specific.
pub const SHT_LOOS: u32 = 0x6000_0000;
/// Object attributes.
pub const SHT_GNU_ATTRIBUTES: u32 = 0x6fff_fff5;
/// GNU-style hash table.
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;
/// Prelink library list.
pub const SHT_GNU_LIBLIST: u32 = 0x6fff_fff7;
/// Checksum for DSO content.
pub const SHT_CHECKSUM: u32 = 0x6fff_fff8;
/// Sun-specific low bound.
pub const SHT_LOSUNW: u32 = 0x6fff_fffa;
pub const SHT_SUNW_MOVE: u32 = 0x6fff_fffa;
pub const SHT_SUNW_COMDAT: u32 = 0x6fff_fffb;
pub const SHT_SUNW_SYMINFO: u32 = 0x6fff_fffc;
/// Version definition section.
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
/// Version needs section.
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
/// Version symbol table.
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
/// Sun-specific high bound.
pub const SHT_HISUNW: u32 = 0x6fff_ffff;
/// End OS-specific type.
pub const SHT_HIOS: u32 = 0x6fff_ffff;
/// Start of processor-specific.
pub const SHT_LOPROC: u32 = 0x7000_0000;
/// X86-64 unwind information.
pub const SHT_X86_64_UNWIND: u32 = 0x7000_0001;
/// End of processor-specific.
pub const SHT_HIPROC: u32 = 0x7fff_ffff;
/// Start of application-specific.
pub const SHT_LOUSER: u32 = 0x8000_0000;
/// End of application-specific.
pub const SHT_HIUSER: u32 = 0x8fff_ffff;

/// Marks end of dynamic section
pub const DT_NULL: u64 = 0;
/// Name of needed library
pub const DT_NEEDED: u64 = 1;
/// Size in bytes of PLT relocs
pub const DT_PLTRELSZ: u64 = 2;
/// Processor defined value
pub const DT_PLTGOT: u64 = 3;
/// Address of symbol hash table
pub const DT_HASH: u64 = 4;
/// Address of string table
pub const DT_STRTAB: u64 = 5;
/// Address of symbol table
pub const DT_SYMTAB: u64 = 6;
/// Address of Rela relocs
pub const DT_RELA: u64 = 7;
/// Total size of Rela relocs
pub const DT_RELASZ: u64 = 8;
/// Size of one Rela reloc
pub const DT_RELAENT: u64 = 9;
/// Size of string table
pub const DT_STRSZ: u64 = 10;
/// Size of one symbol table entry
pub const DT_SYMENT: u64 = 11;
/// Address of init function
pub const DT_INIT: u64 = 12;
/// Address of termination function
pub const DT_FINI: u64 = 13;
/// Name of shared object
pub const DT_SONAME: u64 = 14;
/// Library search path (deprecated)
pub const DT_RPATH: u64 = 15;
/// Start symbol search here
pub const DT_SYMBOLIC: u64 = 16;
/// Address of Rel relocs
pub const DT_REL: u64 = 17;
/// Total size of Rel relocs
pub const DT_RELSZ: u64 = 18;
/// Size of one Rel reloc
pub const DT_RELENT: u64 = 19;
/// Type of reloc in PLT
pub const DT_PLTREL: u64 = 20;
/// For debugging; unspecified
pub const DT_DEBUG: u64 = 21;
/// Reloc might modify .text
pub const DT_TEXTREL: u64 = 22;
/// Address of PLT relocs
pub const DT_JMPREL: u64 = 23;
/// Process relocations of object
pub const DT_BIND_NOW: u64 = 24;
/// Array with addresses of init fct
pub const DT_INIT_ARRAY: u64 = 25;
/// Array with addresses of fini fct
pub const DT_FINI_ARRAY: u64 = 26;
/// Size in bytes of DT_INIT_ARRAY
pub const DT_INIT_ARRAYSZ: u64 = 27;
/// Size in bytes of DT_FINI_ARRAY
pub const DT_FINI_ARRAYSZ: u64 = 28;
/// Library search path
pub const DT_RUNPATH: u64 = 29;
/// Flags for the object being loaded
pub const DT_FLAGS: u64 = 30;
/// Start of encoded range
// pub const DT_ENCODING: u64 = 32;
/// Array with addresses of preinit fct
pub const DT_PREINIT_ARRAY: u64 = 32;
/// size in bytes of DT_PREINIT_ARRAY
pub const DT_PREINIT_ARRAYSZ: u64 = 33;
/// Number used
pub const DT_NUM: u64 = 34;
/// Start of OS-specific
pub const DT_LOOS: u64 = 0x6000_000d;
/// End of OS-specific
pub const DT_HIOS: u64 = 0x6fff_f000;
/// Start of processor-specific
pub const DT_LOPROC: u64 = 0x7000_0000;
/// End of processor-specific
pub const DT_HIPROC: u64 = 0x7fff_ffff;
// Most used by any processor
// pub const DT_PROCNUM: u64 = DT_MIPS_NUM;

/// DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
/// Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
///
/// If any adjustment is made to the ELF object after it has been
/// built these entries will need to be adjusted.
// pub const DT_ADDRRNGLO: u64 = 0x6fff_fe00;
/// GNU-style hash table
pub const DT_GNU_HASH: u64 = 0x6fff_fef5;
///
// pub const DT_TLSDESC_PLT: u64 = 0x6fff_fef6;
///
// pub const DT_TLSDESC_GOT: u64 = 0x6fff_fef7;
/// Start of conflict section
// pub const DT_GNU_CONFLICT: u64 = 0x6fff_fef8;
/// Library list
// pub const DT_GNU_LIBLIST: u64 = 0x6fff_fef9;
/// Configuration information
// pub const DT_CONFIG: u64 = 0x6fff_fefa;
/// Dependency auditing
// pub const DT_DEPAUDIT: u64 = 0x6fff_fefb;
/// Object auditing
// pub const DT_AUDIT: u64 = 0x6fff_fefc;
/// PLT padding
// pub const DT_PLTPAD: u64 = 0x6fff_fefd;
/// Move table
// pub const DT_MOVETAB: u64 = 0x6fff_fefe;
/// Syminfo table
// pub const DT_SYMINFO: u64 = 0x6fff_feff;
///
// pub const DT_ADDRRNGHI: u64 = 0x6fff_feff;

//DT_ADDRTAGIDX(tag)	(DT_ADDRRNGHI - (tag))	/* Reverse order! */
// pub const DT_ADDRNUM: u64 = 11;

/// The versioning entry types. The next are defined as part of the GNU extension
pub const DT_VERSYM: u64 = 0x6fff_fff0;
pub const DT_RELACOUNT: u64 = 0x6fff_fff9;
pub const DT_RELCOUNT: u64 = 0x6fff_fffa;
/// State flags, see DF_1_* below
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;
/// Address of version definition table
pub const DT_VERDEF: u64 = 0x6fff_fffc;
/// Number of version definitions
pub const DT_VERDEFNUM: u64 = 0x6fff_fffd;
/// Address of table with needed versions
pub const DT_VERNEED: u64 = 0x6fff_fffe;
/// Number of needed versions
pub const DT_VERNEEDNUM: u64 = 0x6fff_ffff;

/// Converts a tag to its string representation.
#[inline]
pub fn tag_to_str(tag: u64) -> &'static str {
    match tag {
        DT_NULL => "DT_NULL",
        DT_NEEDED => "DT_NEEDED",
        DT_PLTRELSZ => "DT_PLTRELSZ",
        DT_PLTGOT => "DT_PLTGOT",
        DT_HASH => "DT_HASH",
        DT_STRTAB => "DT_STRTAB",
        DT_SYMTAB => "DT_SYMTAB",
        DT_RELA => "DT_RELA",
        DT_RELASZ => "DT_RELASZ",
        DT_RELAENT => "DT_RELAENT",
        DT_STRSZ => "DT_STRSZ",
        DT_SYMENT => "DT_SYMENT",
        DT_INIT => "DT_INIT",
        DT_FINI => "DT_FINI",
        DT_SONAME => "DT_SONAME",
        DT_RPATH => "DT_RPATH",
        DT_SYMBOLIC => "DT_SYMBOLIC",
        DT_REL => "DT_REL",
        DT_RELSZ => "DT_RELSZ",
        DT_RELENT => "DT_RELENT",
        DT_PLTREL => "DT_PLTREL",
        DT_DEBUG => "DT_DEBUG",
        DT_TEXTREL => "DT_TEXTREL",
        DT_JMPREL => "DT_JMPREL",
        DT_BIND_NOW => "DT_BIND_NOW",
        DT_INIT_ARRAY => "DT_INIT_ARRAY",
        DT_FINI_ARRAY => "DT_FINI_ARRAY",
        DT_INIT_ARRAYSZ => "DT_INIT_ARRAYSZ",
        DT_FINI_ARRAYSZ => "DT_FINI_ARRAYSZ",
        DT_RUNPATH => "DT_RUNPATH",
        DT_FLAGS => "DT_FLAGS",
        // DT_ENCODING => "DT_ENCODING",
        DT_PREINIT_ARRAY => "DT_PREINIT_ARRAY",
        DT_PREINIT_ARRAYSZ => "DT_PREINIT_ARRAYSZ",
        DT_NUM => "DT_NUM",
        DT_LOOS => "DT_LOOS",
        DT_HIOS => "DT_HIOS",
        DT_LOPROC => "DT_LOPROC",
        DT_HIPROC => "DT_HIPROC",
        DT_VERSYM => "DT_VERSYM",
        DT_RELACOUNT => "DT_RELACOUNT",
        DT_RELCOUNT => "DT_RELCOUNT",
        DT_GNU_HASH => "DT_GNU_HASH",
        DT_VERDEF => "DT_VERDEF",
        DT_VERDEFNUM => "DT_VERDEFNUM",
        DT_VERNEED => "DT_VERNEED",
        DT_VERNEEDNUM => "DT_VERNEEDNUM",
        DT_FLAGS_1 => "DT_FLAGS_1",
        _ => "UNKNOWN_TAG",
    }
}

#[derive(Default, Pread, Pwrite)]
pub struct ELFHeader64 {
    /// Magic number and other info
    pub e_ident: [u8; 16], // const SIZEOF_IDENT: usize = 16;
    /// Object file type
    pub e_type: u16,
    /// Architecture
    pub e_machine: u16,
    /// Object file version
    pub e_version: u32,
    /// Entry point virtual address
    pub e_entry: u64,
    /// Program header table file offset
    pub e_phoff: u64,
    /// Section header table file offset
    pub e_shoff: u64,
    /// Processor-specific flags
    pub e_flags: u32,
    /// ELF header size in bytes
    pub e_ehsize: u16,
    /// Program header table entry size
    pub e_phentsize: u16,
    /// Program header table entry count
    pub e_phnum: u16,
    /// Section header table entry size
    pub e_shentsize: u16,
    /// Section header table entry count
    pub e_shnum: u16,
    /// Section header string table index
    pub e_shstrndx: u16,
}

/// Convert an ET value to their associated string.
#[inline]
pub fn et_to_str(et: u16) -> &'static str {
    match et {
        ET_NONE => "NONE",
        ET_REL => "REL",
        ET_EXEC => "EXEC",
        ET_DYN => "DYN",
        ET_CORE => "CORE",
        ET_NUM => "NUM",
        _ => "UNKNOWN_ET",
    }
}

impl fmt::Debug for ELFHeader64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("e_ident", &format_args!("{:?}", self.e_ident))
            .field("e_type", &et_to_str(self.e_type))
            .field("e_machine", &format_args!("0x{:x}", self.e_machine))
            .field("e_version", &format_args!("0x{:x}", self.e_version))
            .field("e_entry", &format_args!("0x{:x}", self.e_entry))
            .field("e_phoff", &format_args!("0x{:x}", self.e_phoff))
            .field("e_shoff", &format_args!("0x{:x}", self.e_shoff))
            .field("e_flags", &format_args!("{:x}", self.e_flags))
            .field("e_ehsize", &self.e_ehsize)
            .field("e_phentsize", &self.e_phentsize)
            .field("e_phnum", &self.e_phnum)
            .field("e_shentsize", &self.e_shentsize)
            .field("e_shnum", &self.e_shnum)
            .field("e_shstrndx", &self.e_shstrndx)
            .finish()
    }
}

#[derive(Pread, Pwrite, Default)]
pub struct ProgramHeader {
    /// Segment type
    pub p_type: u32, // 4
    /// Segment flags
    pub p_flags: u32, // 4
    /// Segment file offset
    pub p_offset: u64, // 8
    /// Segment virtual address
    pub p_vaddr: u64, // 8
    /// Segment physical address
    pub p_paddr: u64, // 8
    /// Segment size in file
    pub p_filesz: u64, // 8
    /// Segment size in memory
    pub p_memsz: u64, // 8
    /// Segment alignment
    pub p_align: u64, // 8
}

pub fn pt_to_str(pt: u32) -> &'static str {
    match pt {
        PT_NULL => "PT_NULL",
        PT_LOAD => "PT_LOAD",
        PT_DYNAMIC => "PT_DYNAMIC",
        PT_INTERP => "PT_INTERP",
        PT_NOTE => "PT_NOTE",
        PT_SHLIB => "PT_SHLIB",
        PT_PHDR => "PT_PHDR",
        PT_TLS => "PT_TLS",
        PT_NUM => "PT_NUM",
        PT_LOOS => "PT_LOOS",
        PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
        PT_GNU_STACK => "PT_GNU_STACK",
        PT_GNU_RELRO => "PT_GNU_RELRO",
        PT_SUNWBSS => "PT_SUNWBSS",
        PT_SUNWSTACK => "PT_SUNWSTACK",
        PT_HIOS => "PT_HIOS",
        PT_LOPROC => "PT_LOPROC",
        PT_HIPROC => "PT_HIPROC",
        PT_ARM_EXIDX => "PT_ARM_EXIDX",
        _ => "UNKNOWN_PT",
    }
}

impl ProgramHeader {
    /// Whether this program header is executable
    pub fn is_executable(&self) -> bool {
        self.p_flags & PF_X != 0
    }

    /// Whether this program header is writable
    pub fn is_write(&self) -> bool {
        self.p_flags & PF_W != 0
    }
}

impl fmt::Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ProgramHeader")
            .field("p_type", &pt_to_str(self.p_type))
            .field("p_flags", &format_args!("0x{:x}", self.p_flags))
            .field("p_offset", &format_args!("0x{:x}", self.p_offset))
            .field("p_vaddr", &format_args!("0x{:x}", self.p_vaddr))
            .field("p_paddr", &format_args!("0x{:x}", self.p_paddr))
            .field("p_filesz", &format_args!("0x{:x}", self.p_filesz))
            .field("p_memsz", &format_args!("0x{:x}", self.p_memsz))
            .field("p_align", &self.p_align)
            .finish()
    }
}

#[derive(Clone)]
pub struct ProgramHeaders<'a> {
    entries: &'a [u8],
    index: usize,
    e_phnum: usize,
}

impl<'a> ProgramHeaders<'a> {
    // section entries byties, num_sections: total sections
    fn parse(entries: &'a [u8], e_phnum: usize) -> Option<Self> {
        Some(ProgramHeaders {
            index: 0,
            entries,
            e_phnum,
        })
    }
}

impl<'a> Iterator for ProgramHeaders<'a> {
    type Item = ProgramHeader;
    fn next(&mut self) -> Option<Self::Item> {
        const ENTRY_SIZE: usize = 56;
        if self.index == self.e_phnum {
            return None;
        }
        let offset = self.index.checked_mul(ENTRY_SIZE)?;

        let current_bytes = &self.entries[offset..];

        let obj = current_bytes.pread::<ProgramHeader>(0).ok()?;

        self.index += 1;
        Some(obj)
    }
}

#[derive(Pread, Default, Debug)]
pub struct SectionHeader {
    /// Section name (string tbl index)
    pub sh_name: u32,
    /// Section type
    pub sh_type: u32,
    /// Section flags
    pub sh_flags: u64,
    /// Section virtual addr at execution
    pub sh_addr: u64,
    /// Section file offset
    pub sh_offset: u64,
    /// Section size in bytes
    pub sh_size: u64,
    /// Link to another section
    pub sh_link: u32,
    /// Additional section information
    pub sh_info: u32,
    /// Section alignment
    pub sh_addralign: u64,
    /// Entry size if section holds table
    pub sh_entsize: u64,
}

impl SectionHeader {
    pub fn vm_range(&self) -> Range<usize> {
        self.sh_addr as usize
            ..self
                .sh_addr
                .checked_add(self.sh_size)
                .expect("Add with overflow") as usize
    }
}

#[derive(Clone)]
pub struct SectionHeaders<'a> {
    entries: &'a [u8],
    index: usize,
    e_shnum: usize,
}

impl<'a> SectionHeaders<'a> {
    // section entries byties, num_sections: total sections
    fn parse(entries: &'a [u8], e_shnum: usize) -> Option<Self> {
        Some(SectionHeaders {
            index: 0,
            entries,
            e_shnum,
        })
    }
}

impl<'a> Iterator for SectionHeaders<'a> {
    type Item = SectionHeader;
    fn next(&mut self) -> Option<Self::Item> {
        const ENTRY_SIZE: usize = 64;
        if self.index == self.e_shnum {
            return None;
        }
        let offset = self.index.checked_mul(ENTRY_SIZE)?;

        let current_bytes = &self.entries[offset..];

        let obj = current_bytes.pread::<SectionHeader>(0).ok()?;
        self.index += 1;
        Some(obj)
    }
}

#[derive(Pread, Pwrite, Default)]
pub struct Dyn {
    pub d_tag: u64,
    pub d_val: u64,
}

impl fmt::Debug for Dyn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Dyn")
            .field("d_tag", &tag_to_str(self.d_tag))
            .field("d_value", &format_args!("0x{:x}", self.d_val))
            .finish()
    }
}

struct Dyns<'a> {
    entries: &'a [u8],
    index: usize,
    entries_len: usize,
}

impl<'a> Dyns<'a> {
    // section entries byties, num_sections: total sections
    fn parse(entries: &'a [u8], entries_len: usize) -> Option<Self> {
        Some(Dyns {
            index: 0,
            entries,
            entries_len,
        })
    }
}

impl<'a> Iterator for Dyns<'a> {
    type Item = Dyn;
    fn next(&mut self) -> Option<Self::Item> {
        const ENTRY_SIZE: usize = 16;
        if self.index.saturating_mul(ENTRY_SIZE) >= self.entries_len {
            return None;
        }
        let offset = self.index.checked_mul(ENTRY_SIZE)?;

        let current_bytes = &self.entries[offset..];

        let obj = current_bytes.pread::<Dyn>(0).ok()?;

        self.index += 1;
        Some(obj)
    }
}

/// Convert a virtual memory address to a file offset
fn vm_to_offset(phdrs: ProgramHeaders, address: u64) -> Option<u64> {
    for ph in phdrs {
        if address >= ph.p_vaddr {
            let offset = address - ph.p_vaddr;
            if offset < ph.p_memsz {
                return ph.p_offset.checked_add(offset);
            }
        }
    }
    None
}

#[derive(Default, PartialEq)]
pub struct DynamicInfo {
    pub rela: usize,
    pub relasz: usize,
    pub relaent: usize,
    pub relacount: usize,
}

#[derive(Pread, Pwrite, Default)]
/// A unified ELF relocation structure
pub struct Rela {
    /// Address
    pub r_offset: u64,
    /// Relocation type and symbol index
    pub r_info: u64,
    /// Addend
    pub r_addend: i64,
}

impl Rela {
    #[inline(always)]
    pub fn r_sym(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    #[inline(always)]
    pub fn r_type(&self) -> u32 {
        (self.r_info & 0xffff_ffff) as u32
    }
}

impl fmt::Debug for Rela {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Reloc")
            .field("r_offset", &format_args!("{:x}", self.r_offset))
            .field("r_addend", &format_args!("{:x}", self.r_addend))
            .field("r_sym", &self.r_sym())
            .field("r_type", &self.r_type())
            .finish()
    }
}
pub struct Relocs<'a> {
    entries: &'a [u8],
    index: usize,
    relacount: usize,
    relaent: usize,
}

impl<'a> Relocs<'a> {
    // section entries byties, num_sections: total sections
    pub fn parse(entries: &'a [u8], relacount: usize, relaent: usize) -> Option<Self> {
        Some(Relocs {
            index: 0,
            entries,
            relacount,
            relaent,
        })
    }
}

impl<'a> Iterator for Relocs<'a> {
    type Item = Rela;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.relacount {
            return None;
        }

        if self.relaent == 0 {
            return None;
        }

        let offset = self.index.checked_mul(self.relaent)?;
        self.entries.len().checked_sub(offset)?;
        let current_bytes = &self.entries[offset..];

        let obj = current_bytes.pread::<Rela>(0).ok()?;

        self.index += 1;
        Some(obj)
    }
}

pub struct Elf<'a> {
    bytes: &'a [u8],
    pub header: ELFHeader64,
}

impl<'a> Elf<'a> {
    pub fn parse(elf_bin: &'a [u8]) -> Option<Self> {
        let header = elf_bin.pread::<ELFHeader64>(0).ok()?;
        if header.e_phoff > elf_bin.len() as u64 || header.e_shoff > elf_bin.len() as u64 {
            return None;
        }
        Some(Elf {
            header,
            bytes: elf_bin,
        })
    }

    fn dynamic_info(&self) -> Option<DynamicInfo> {
        let elf_bin = self.bytes;
        let mut dynamic_info = DynamicInfo::default();
        for header in self.program_headers() {
            if header.p_type == PT_DYNAMIC {
                if header.p_offset.checked_add(header.p_filesz)? > elf_bin.len() as u64 {
                    return None;
                }
                let dyns = Dyns::parse(
                    &elf_bin[header.p_offset as usize..],
                    header.p_filesz as usize,
                )?;
                for d in dyns {
                    if d.d_tag == DT_RELA {
                        dynamic_info.rela = vm_to_offset(self.program_headers(), d.d_val)? as usize;
                    }
                    if d.d_tag == DT_RELACOUNT {
                        dynamic_info.relacount = d.d_val as usize;
                    }
                    if d.d_tag == DT_RELAENT {
                        dynamic_info.relaent = d.d_val as usize;
                    }
                    if d.d_tag == DT_RELASZ {
                        dynamic_info.relasz = d.d_val as usize;
                    }
                }
            }
        }
        Some(dynamic_info)
    }

    pub fn program_headers(&self) -> ProgramHeaders<'a> {
        let bytes = &self.bytes[self.header.e_phoff as usize..];
        ProgramHeaders::parse(bytes, self.header.e_phnum as usize).unwrap()
    }

    pub fn section_headers(&self) -> SectionHeaders<'a> {
        let bytes = &self.bytes[self.header.e_shoff as usize..];
        SectionHeaders::parse(bytes, self.header.e_shnum as usize).unwrap()
    }

    pub fn relocations(&self) -> Option<Relocs<'a>> {
        let elf_bin = self.bytes;

        let dynamic_info = self.dynamic_info()?;
        elf_bin.len().checked_sub(dynamic_info.rela)?;
        let relocs = Relocs::parse(
            &elf_bin[dynamic_info.rela..],
            dynamic_info.relacount,
            dynamic_info.relaent,
        )?;
        Some(relocs)
    }
}

#[cfg(test)]
mod test_elf_loader {
    use super::*;

    #[test]
    fn test_elfheader() {
        let pe_image = &include_bytes!("../../data/blobs/td-payload.elf")[..];

        let elf = crate::elf64::Elf::parse(pe_image).unwrap();
        println!("{:?}\n", elf.header);

        let hd = elf.program_headers().next().unwrap();
        let status = hd.is_executable();
        assert!(!status);

        let status = hd.is_write();
        assert!(!status);

        let elf_bin = elf.bytes;
        for header in elf.program_headers() {
            println!("header: {:?}\n", header);

            let dyns = Dyns::parse(
                &elf_bin[header.p_offset as usize..],
                header.p_filesz as usize,
            )
            .unwrap();
            for d in dyns {
                println!("{:?}", d);
            }
        }

        for header in elf.section_headers() {
            println!("header: {:?}\n", header);

            assert_eq!(
                header.vm_range(),
                header.sh_addr as usize..(header.sh_addr + header.sh_size) as usize
            )
        }

        for relocs in elf.relocations() {
            for rel in relocs {
                println!("rel:{:?}", rel);
                println!("rel_info:{:?}", rel.r_sym() as u64 + rel.r_type() as u64);
            }
        }
    }

    #[test]
    fn test_to_str() {
        let str_slice_16 = [ET_NONE, ET_REL, ET_EXEC, ET_DYN, ET_CORE, ET_NUM];
        let str_slice_64 = [
            DT_JMPREL,
            DT_BIND_NOW,
            DT_INIT_ARRAY,
            DT_NUM,
            DT_LOOS,
            DT_HIOS,
            DT_LOPROC,
            DT_HIPROC,
            DT_VERSYM,
            DT_VERDEF,
            DT_VERDEFNUM,
            DT_VERNEED,
            DT_VERNEEDNUM,
            DT_RELCOUNT,
            DT_FINI,
            DT_RELENT,
            DT_PLTREL,
            DT_FINI_ARRAY,
            DT_INIT_ARRAYSZ,
            DT_FINI_ARRAYSZ,
            DT_FINI_ARRAYSZ,
            DT_FLAGS,
        ];
        let str_slice_32 = [
            PT_NULL,
            PT_LOAD,
            PT_DYNAMIC,
            PT_INTERP,
            PT_NOTE,
            PT_SHLIB,
            PT_PHDR,
            PT_TLS,
            PT_NUM,
            PT_LOOS,
            PT_GNU_EH_FRAME,
            PT_GNU_STACK,
            PT_GNU_RELRO,
            PT_SUNWBSS,
            PT_SUNWSTACK,
            PT_HIOS,
            PT_LOPROC,
            PT_HIPROC,
            PT_ARM_EXIDX,
        ];

        for d in str_slice_16.iter() {
            let str = et_to_str(*d);
            println!("{:?}", &str);
        }
        for d in str_slice_32.iter() {
            let str = pt_to_str(*d);
            println!("{:?}", &str);
        }
        for d in str_slice_64.iter() {
            let str = tag_to_str(*d);
            println!("{:?}", &str);
        }
    }

    #[test]
    #[should_panic(expected = "Add with overflow")]
    fn test_vm_range() {
        let mut hdr = SectionHeader::default();
        hdr.sh_addr = u64::MAX;
        hdr.sh_size = 0x1;
        hdr.vm_range();
    }
}

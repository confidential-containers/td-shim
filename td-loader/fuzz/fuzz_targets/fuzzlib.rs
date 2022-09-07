// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]
use td_loader::{elf, elf64::*};

pub fn fuzz_elf_loader(data: &[u8]) {
    if !elf::is_elf(data) {
        return;
    }
    let mut loaded_buffer = vec![0u8; 0x800000];

    elf::relocate_elf_with_per_program_header(&data[..], loaded_buffer.as_mut_slice());
    let _ = elf::parse_pre_init_array_section(data);
    let _ = elf::parse_init_array_section(data);
    let _ = elf::parse_finit_array_section(data);

    if let Some(elf) = Elf::parse(data) {
        log::info!("{:?}\n", elf.header);

        if let Some(hd) = elf.program_headers().unwrap().next() {
            let status = hd.is_executable();
            log::info!("executable status: {}", status);
            let status = hd.is_write();
            log::info!("write status: {}", status);
        }

        for header in elf.program_headers().unwrap() {
            log::info!("header: {:?}\n", header);
        }

        for relocs in elf.relocations() {
            for rel in relocs {
                log::info!("rel:{:?}", rel);
            }
        }
    }

    let str_slice_16 = [ET_NONE, ET_REL, ET_EXEC, ET_DYN, ET_NONE, ET_NUM];
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
        DT_PLTRELSZ,
        DT_PLTGOT,
        DT_HASH,
        DT_STRTAB,
        DT_SYMTAB,
        DT_RELAENT,
        DT_RELASZ,
        DT_RELAENT,
        DT_STRSZ,
        DT_SYMENT,
        DT_INIT,
        DT_FINI,
        DT_SONAME,
        DT_RPATH,
        DT_SYMBOLIC,
        DT_REL,
        DT_RELSZ,
        DT_RELENT,
        DT_PLTREL,
        DT_DEBUG,
        DT_TEXTREL,
        DT_JMPREL,
        DT_BIND_NOW,
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
        log::info!("{:?}", &str);
    }
    for d in str_slice_32.iter() {
        let str = pt_to_str(*d);
        log::info!("{:?}", &str);
    }
    for d in str_slice_64.iter() {
        let str = tag_to_str(*d);
        log::info!("{:?}", &str);
    }
}

use td_loader::pe::{is_x86_64_pe, relocate, relocate_pe_mem_with_per_sections, Sections};

pub fn fuzz_pe_loader(data: &[u8]) {
    if is_x86_64_pe(data) {
        let sections = Sections::parse(data, 5 as usize);
        if sections.is_some() {
            let sections = sections.unwrap();
            for section in sections {
                log::info!("{:?}", section);
            }

            let mut loaded_buffer = vec![0u8; 0x200000];

            relocate(data, loaded_buffer.as_mut_slice(), 0x100000);

            relocate_pe_mem_with_per_sections(data, loaded_buffer.as_mut_slice());
        }
    }
}

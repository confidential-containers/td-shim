// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(not(feature = "no-td-hob"))]
use core::mem::size_of;

use lazy_static::lazy_static;
#[cfg(not(feature = "no-td-hob"))]
use scroll::Pread;
use spin::{Mutex, Once};
use td_shim::e820::{E820Entry, E820Type};
#[cfg(not(feature = "no-td-hob"))]
use td_shim::TD_E820_TABLE_HOB_GUID;
#[cfg(not(feature = "no-td-hob"))]
use td_shim_interface::td_uefi_pi::{
    hob as hob_lib,
    pi::hob::{GuidExtension, Header, HOB_TYPE_END_OF_HOB_LIST, HOB_TYPE_GUID_EXTENSION},
};
#[cfg(not(feature = "no-td-hob"))]
use zerocopy::FromBytes;

#[cfg(not(feature = "no-td-hob"))]
use crate::Error;

#[cfg(any(target_os = "none", target_os = "uefi"))]
pub(crate) mod heap;
#[cfg(feature = "tdx")]
pub mod shared;
#[cfg(not(any(target_os = "none", target_os = "uefi")))]
pub(crate) mod heap {
    // A null implementation used by test
    pub fn init_heap(_heap_start: u64, _heap_size: usize) {}
}
pub mod layout;
pub(crate) mod page_table;

pub const E820_TABLE_SIZE: usize = 128;
pub const SIZE_4K: usize = 0x1000;
pub const SIZE_2M: usize = 0x20_0000;
pub const SIZE_1G: usize = 0x4000_0000;

lazy_static! {
    pub static ref MEMORY_MAP: Mutex<[E820Entry; E820_TABLE_SIZE]> =
        Mutex::new([E820Entry::default(); E820_TABLE_SIZE]);
}
static END_OF_RAM: Once<usize> = Once::new();

#[cfg(not(feature = "no-td-hob"))]
pub fn init_ram(hob: &'static [u8]) -> Result<&'static [E820Entry], Error> {
    let e820_table = get_e820_table(hob)?;
    init_ram_from_e820(e820_table)
}

#[cfg(not(feature = "no-td-hob"))]
fn init_ram_from_e820(e820_table: &'static [E820Entry]) -> Result<&'static [E820Entry], Error> {
    let end_of_ram = e820_table
        .iter()
        .map(|entry| (entry.addr + entry.size) as usize)
        .max()
        .ok_or(Error::GetMemoryMap)?;
    END_OF_RAM.call_once(|| end_of_ram);

    MEMORY_MAP.lock()[..e820_table.len()].copy_from_slice(e820_table);

    Ok(e820_table)
}

pub fn end_of_ram() -> usize {
    // `END_OF_RAM` must have been initialized
    *END_OF_RAM.get().unwrap()
}

pub fn get_usable(size: usize) -> Option<u64> {
    let table = &mut *MEMORY_MAP.lock();

    for entry in table.iter_mut() {
        if *entry == E820Entry::default() {
            break;
        }

        if entry.r#type == E820Type::Memory as u32 && entry.size >= size as u64 {
            entry.size -= size as u64;
            return Some(entry.addr + entry.size);
        }
    }

    None
}

#[cfg(feature = "no-td-hob")]
pub fn init_ram_from_metadata() -> &'static [E820Entry] {
    use td_layout::runtime::exec::MEMORY_LAYOUT_CONFIG;

    static METADATA_E820: Once<[E820Entry; E820_TABLE_SIZE]> = Once::new();

    let table = METADATA_E820.call_once(|| {
        let mut entries = [E820Entry::default(); E820_TABLE_SIZE];
        let mut addr: u64 = 0;
        let mut idx = 0;

        for &(_, size, mem_type) in MEMORY_LAYOUT_CONFIG {
            let e820_type = match mem_type {
                "Memory" => E820Type::Memory,
                "Reserved" => E820Type::Reserved,
                "Acpi" => E820Type::Acpi,
                "Nvs" => E820Type::Nvs,
                _ => E820Type::Reserved,
            };
            entries[idx] = E820Entry {
                addr,
                size: size as u64,
                r#type: e820_type as u32,
            };
            addr += size as u64;
            idx += 1;
        }
        entries
    });

    let count = table
        .iter()
        .take_while(|e| **e != E820Entry::default())
        .count();
    let e820 = &table[..count];

    let end_of_ram = e820
        .iter()
        .map(|entry| (entry.addr + entry.size) as usize)
        .max()
        .expect("Empty metadata memory layout");
    END_OF_RAM.call_once(|| end_of_ram);

    MEMORY_MAP.lock()[..count].copy_from_slice(e820);

    e820
}

#[cfg(not(feature = "no-td-hob"))]
fn get_e820_table(hob: &'static [u8]) -> Result<&'static [E820Entry], Error> {
    let mut offset = 0;

    loop {
        let block = &hob[offset..];
        let header = block.pread::<Header>(0).map_err(|_| Error::ParseHob)?;
        match header.r#type {
            HOB_TYPE_GUID_EXTENSION => {
                let header = block
                    .pread::<GuidExtension>(0)
                    .map_err(|_| Error::ParseHob)?;
                if &header.name == TD_E820_TABLE_HOB_GUID.as_bytes() {
                    return parse_guided_hob(block).ok_or(Error::GetMemoryMap);
                }
            }
            HOB_TYPE_END_OF_HOB_LIST => {
                // End of the hob list, break the loop
                break;
            }
            _ => {}
        }
        offset = hob_lib::align_to_next_hob_offset(hob.len(), offset, header.length)
            .ok_or(Error::ParseHob)?;
    }

    Err(Error::GetMemoryMap)
}

#[cfg(not(feature = "no-td-hob"))]
fn parse_guided_hob(guided_hob: &'static [u8]) -> Option<&'static [E820Entry]> {
    let table = hob_lib::get_guid_data(guided_hob)?;
    let mut entry_num = table.len() / size_of::<E820Entry>();

    let last_entry = E820Entry::read_from_bytes(
        &table[(entry_num - 1) * size_of::<E820Entry>()..entry_num * size_of::<E820Entry>()],
    )
    .ok()?;

    // Ignore the padding zeros in GUIDed HOB
    if last_entry == E820Entry::default() {
        entry_num -= 1;
    }

    if entry_num == 0 || entry_num > E820_TABLE_SIZE {
        return None;
    }

    Some(unsafe { core::slice::from_raw_parts(table.as_ptr() as *const E820Entry, entry_num) })
}

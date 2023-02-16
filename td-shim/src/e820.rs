// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use zerocopy::{AsBytes, FromBytes};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum E820Type {
    Memory = 1,
    Reserved = 2,
    Acpi = 3,
    Nvs = 4,
    Unusable = 5,
    Disabled = 6,
    Pmem = 7,
    Unaccepted = 8,
    Unknown = 0xff,
}

impl From<&str> for E820Type {
    fn from(str: &str) -> Self {
        match str {
            "Memory" => E820Type::Memory,
            "Reserved" => E820Type::Reserved,
            "Acpi" => E820Type::Acpi,
            "Nvs" => E820Type::Nvs,
            "Unusable" => E820Type::Unusable,
            "Disabled" => E820Type::Disabled,
            "Pmem" => E820Type::Pmem,
            "Unaccepted" => E820Type::Unaccepted,
            "Unknown" => E820Type::Unknown,
            _ => E820Type::Unknown,
        }
    }
}

impl From<u32> for E820Type {
    fn from(i: u32) -> Self {
        match i {
            1 => E820Type::Memory,
            2 => E820Type::Reserved,
            3 => E820Type::Acpi,
            4 => E820Type::Nvs,
            5 => E820Type::Unusable,
            6 => E820Type::Disabled,
            7 => E820Type::Pmem,
            8 => E820Type::Unaccepted,
            _ => E820Type::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, FromBytes, AsBytes, PartialEq)]
#[repr(C, packed)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub r#type: u32,
}

impl E820Entry {
    pub fn new(addr: u64, size: u64, r#type: E820Type) -> Self {
        E820Entry {
            addr,
            size,
            r#type: r#type as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;
    const MAX_E820_ENTRY: usize = 128;

    #[test]
    fn test_e820_entry_size() {
        assert_eq!(size_of::<E820Entry>(), 20);
        assert_eq!(
            size_of::<[E820Entry; MAX_E820_ENTRY]>(),
            20 * MAX_E820_ENTRY
        );
    }

    #[test]
    fn test_e820_entry() {
        let _entry = E820Entry::new(0x1000, 0x1000, E820Type::Memory);
    }

    #[test]
    fn test_e820_type() {
        assert_eq!(E820Type::from(1) as u32, E820Type::Memory as u32);
        assert_eq!(E820Type::from(2) as u32, E820Type::Reserved as u32);
        assert_eq!(E820Type::from(3) as u32, E820Type::Acpi as u32);
        assert_eq!(E820Type::from(4) as u32, E820Type::Nvs as u32);
        assert_eq!(E820Type::from(5) as u32, E820Type::Unusable as u32);
        assert_eq!(E820Type::from(6) as u32, E820Type::Disabled as u32);
        assert_eq!(E820Type::from(7) as u32, E820Type::Pmem as u32);
        assert_eq!(E820Type::from(8) as u32, E820Type::Unaccepted as u32);
        assert_eq!(E820Type::from(0xff) as u32, E820Type::Unknown as u32);
    }
}

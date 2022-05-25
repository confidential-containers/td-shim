// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use zerocopy::{AsBytes, FromBytes};

#[derive(Clone, Copy)]
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
}

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub use td_layout::E820Type;
use zerocopy::{AsBytes, FromBytes};

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

// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub const ACPI_TABLES_MAX_NUM: usize = 20;
pub const ACPI_RSDP_REVISION: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidParameter,
    TooManyAcpiTables,
}

pub fn calculate_checksum(data: &[u8]) -> u8 {
    (255 - data.iter().fold(0u8, |acc, x| acc.wrapping_add(*x))).wrapping_add(1)
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes, FromZeroes)]
pub struct Rsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub _rsdt_addr: u32,
    pub length: u32,
    pub xsdt_addr: u64,
    pub extended_checksum: u8,
    pub _reserved: [u8; 3],
}

impl Rsdp {
    pub fn new(xsdt_addr: u64) -> Rsdp {
        let mut rsdp = Rsdp {
            signature: *b"RSD PTR ",
            checksum: 0,
            oem_id: *b"INTEL ",
            revision: ACPI_RSDP_REVISION,
            length: size_of::<Rsdp>() as u32,
            xsdt_addr,
            ..Default::default()
        };
        rsdp.checksum();
        rsdp
    }

    pub fn set_xsdt(&mut self, xsdt: u64) {
        self.xsdt_addr = xsdt;
        self.checksum();
    }

    fn checksum(&mut self) {
        self.checksum = 0;
        self.extended_checksum = 0;
        self.checksum = calculate_checksum(&self.as_bytes()[0..20]);
        self.extended_checksum = calculate_checksum(self.as_bytes());
    }
}

#[repr(C, packed)]
#[derive(Default, AsBytes, FromBytes, FromZeroes)]
pub struct GenericSdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: u64,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

impl GenericSdtHeader {
    pub fn new(signature: &[u8; 4], length: u32, revision: u8) -> Self {
        GenericSdtHeader {
            signature: *signature,
            length,
            revision,
            checksum: 0,
            oem_id: *b"INTEL ",
            oem_table_id: u64::from_le_bytes(*b"SHIM    "),
            oem_revision: 1,
            creator_id: u32::from_le_bytes(*b"SHIM"),
            creator_revision: 1,
        }
    }

    pub fn set_checksum(&mut self, checksum: u8) {
        self.checksum = checksum;
    }
}

#[repr(C, packed)]
#[derive(Default, AsBytes, FromBytes, FromZeroes)]
pub struct Xsdt {
    pub header: GenericSdtHeader,
    pub tables: [u64; ACPI_TABLES_MAX_NUM],
}

impl Xsdt {
    pub fn new() -> Self {
        Xsdt {
            header: GenericSdtHeader::new(b"XSDT", size_of::<GenericSdtHeader>() as u32, 1),
            tables: [0; ACPI_TABLES_MAX_NUM],
        }
    }

    pub fn add_table(&mut self, addr: u64) -> Result<(), Error> {
        if self.header.length < size_of::<GenericSdtHeader>() as u32 {
            Err(Error::InvalidParameter)
        } else {
            let table_num =
                (self.header.length as usize - size_of::<GenericSdtHeader>()) / size_of::<u64>();
            if table_num < ACPI_TABLES_MAX_NUM {
                self.tables[table_num] = addr;
                self.header.length += size_of::<u64>() as u32;
                Ok(())
            } else {
                Err(Error::TooManyAcpiTables)
            }
        }
    }

    pub fn checksum(&mut self) {
        self.header.set_checksum(0);
        self.header.set_checksum(calculate_checksum(
            &self.as_bytes()[..self.header.length as usize],
        ));
    }
}

#[repr(C, packed)]
#[derive(Default, AsBytes, FromBytes, FromZeroes)]
pub struct Ccel {
    pub header: GenericSdtHeader,
    pub cc_type: u8,
    pub cc_subtype: u8,
    pub reserved: u16,
    pub laml: u64,
    pub lasa: u64,
}

impl Ccel {
    pub fn new(cc_type: u8, cc_subtype: u8, laml: u64, lasa: u64) -> Ccel {
        let mut ccel = Ccel {
            header: GenericSdtHeader::new(b"CCEL", size_of::<Ccel>() as u32, 1),
            cc_type,
            cc_subtype,
            reserved: 0,
            laml,
            lasa,
        };
        ccel.checksum();
        ccel
    }

    pub fn checksum(&mut self) {
        self.header.checksum = 0;
        self.header
            .set_checksum(calculate_checksum(self.as_bytes()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_checksum() {
        let mut buf = [0xac; 8];
        buf[7] = 0;
        buf[7] = calculate_checksum(&buf);
        let sum = buf.iter().fold(0u8, |s, v| s.wrapping_add(*v));
        assert_eq!(sum, 0);

        buf[3] = 0xcd;
        buf[6] = 0x1c;
        buf[4] = 0;
        buf[4] = calculate_checksum(&buf);
        let sum = buf.iter().fold(0u8, |s, v| s.wrapping_add(*v));
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_rsdp() {
        let mut rsdp = Rsdp::new(0xabcd1234);
        let sum = rsdp.as_bytes()[0..20]
            .iter()
            .fold(0u8, |s, v| s.wrapping_add(*v));
        assert_eq!(sum, 0);
        let sum = rsdp.as_bytes().iter().fold(0u8, |s, v| s.wrapping_add(*v));
        assert_eq!(sum, 0);

        rsdp.set_xsdt(0xdeadbeaf);
        let sum = rsdp.as_bytes()[0..20]
            .iter()
            .fold(0u8, |s, v| s.wrapping_add(*v));
        assert_eq!(sum, 0);
        let sum = rsdp.as_bytes().iter().fold(0u8, |s, v| s.wrapping_add(*v));
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_xsdt() {
        const CHECK_SUM: u8 = 186;
        let mut xsdt = Xsdt::new();
        assert_eq!(xsdt.header.length as usize, size_of::<GenericSdtHeader>());
        for idx in 0..ACPI_TABLES_MAX_NUM {
            assert!(!xsdt.add_table(idx as u64).is_err());
            assert_eq!(
                xsdt.header.length as usize,
                size_of::<GenericSdtHeader>() + (idx + 1) * 8
            );
        }

        assert!(xsdt
            .add_table(100)
            .is_err_and(|e| e == Error::TooManyAcpiTables));
        assert_eq!(
            xsdt.header.length as usize,
            size_of::<GenericSdtHeader>() + ACPI_TABLES_MAX_NUM * 8
        );
        assert!(xsdt
            .add_table(101)
            .is_err_and(|e| e == Error::TooManyAcpiTables));
        assert_eq!(
            xsdt.header.length as usize,
            size_of::<GenericSdtHeader>() + ACPI_TABLES_MAX_NUM * 8
        );

        xsdt.checksum();
        assert_eq!(xsdt.header.checksum, CHECK_SUM);
    }

    #[test]
    fn test_ccel() {
        let ccel = Ccel::new(2, 0, 0x100, 0);

        assert_eq!(&ccel.header.signature, b"CCEL");
        assert_eq!(ccel.header.checksum, 45);
    }
}

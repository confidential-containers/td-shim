// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

pub const ACPI_TABLES_MAX_NUM: usize = 20;
pub const ACPI_RSDP_REVISION: u8 = 2;

pub fn calculate_checksum(data: &[u8]) -> u8 {
    (255 - data.iter().fold(0u8, |acc, x| acc.wrapping_add(*x))).wrapping_add(1)
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
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
#[derive(Default, AsBytes, FromBytes)]
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
#[derive(Default, AsBytes, FromBytes)]
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

    pub fn add_table(&mut self, addr: u64) {
        let table_num =
            (self.header.length as usize - size_of::<GenericSdtHeader>()) / size_of::<u64>();
        if table_num < ACPI_TABLES_MAX_NUM {
            self.tables[table_num] = addr as u64;
            self.header.length += size_of::<u64>() as u32;
        } else {
            log::error!("too many ACPI tables, max {}", ACPI_TABLES_MAX_NUM);
        }
    }

    pub fn checksum(&mut self) {
        self.header.set_checksum(0);
        self.header.set_checksum(calculate_checksum(
            &self.as_bytes()[..self.header.length as usize],
        ));
    }
}

#[cfg(feature = "main")]
pub use tables::*;

#[cfg(feature = "main")]
mod tables {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    #[derive(Default)]
    pub struct AcpiTables<'a> {
        acpi_memory: &'a mut [u8],
        pa: u64,
        size: usize,
        fadt: Option<(usize, usize)>, // FADT offset in acpi memory
        dsdt: Option<usize>,          // DSDT offset in acpi memory
        table_offset: Vec<usize>,
    }

    impl<'a> AcpiTables<'a> {
        pub fn new(td_acpi_mem: &'a mut [u8], pa: u64) -> Self {
            AcpiTables {
                acpi_memory: td_acpi_mem,
                pa,
                ..Default::default()
            }
        }

        pub fn finish(&mut self) -> u64 {
            let mut xsdt = Xsdt::new();

            // The Fixed ACPI Description Table (FADT) should always be the first table in XSDT.
            if let Some((fadt_off, fadt_len)) = self.fadt {
                // Safe because DSDT is loaded in acpi_memory which is below 4G
                let dsdt = self
                    .dsdt
                    .as_ref()
                    .map(|v| self.offset_to_address(*v))
                    .unwrap_or_default() as u32;
                let fadt = &mut self.acpi_memory[fadt_off..fadt_off + fadt_len];
                // The Differentiated System Description Table (DSDT) is referred by the FADT table.
                if dsdt != 0 {
                    // The DSDT field of FADT [40..44]
                    dsdt.write_to(&mut fadt[40..44]);
                }

                // Update FADT checksum
                fadt[9] = 0;
                fadt[9] = calculate_checksum(fadt);
                xsdt.add_table(self.offset_to_address(fadt_off));
            }

            for offset in &self.table_offset {
                xsdt.add_table(self.offset_to_address(*offset));
            }

            let xsdt_addr = self.offset_to_address(self.size);
            xsdt.checksum();
            xsdt.write_to(&mut self.acpi_memory[self.size..self.size + size_of::<Xsdt>()]);
            self.size += size_of::<Xsdt>();

            let rsdp_addr = self.offset_to_address(self.size);
            let rsdp = Rsdp::new(xsdt_addr);
            rsdp.write_to(&mut self.acpi_memory[self.size..self.size + size_of::<Rsdp>()]);
            self.size += size_of::<Rsdp>();

            rsdp_addr as u64
        }

        pub fn install(&mut self, table: &[u8]) {
            // Also reserve space for Xsdt and Rsdp
            let total_size = self.size + table.len() + size_of::<Xsdt>() + size_of::<Rsdp>();
            if self.acpi_memory.len() < total_size {
                log::error!(
                    "ACPI content size exceeds limit 0x{:X}",
                    self.acpi_memory.len(),
                );
                return;
            } else if table.len() < size_of::<GenericSdtHeader>() {
                log::error!("ACPI table with length 0x{:X} is invalid", table.len());
                return;
            }

            // Safe because we have checked buffer size.
            let header =
                GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()]).unwrap();
            if header.length as usize > table.len() {
                log::error!(
                    "invalid ACPI table, header length {} is bigger than data length {}",
                    header.length as usize,
                    table.len()
                );
                return;
            }

            if &header.signature == b"FACP" {
                // We will write to the `dsdt` fields at [40-44)
                if header.length < 44 {
                    log::error!("invalid ACPI FADT table");
                    return;
                }
                self.fadt = Some((self.size, header.length as usize));
            } else if &header.signature == b"DSDT" {
                self.dsdt = Some(self.size);
            } else {
                for offset in &self.table_offset {
                    // Safe because it's reading data from our own buffer.
                    let table_header = GenericSdtHeader::read_from(
                        &self.acpi_memory[*offset..*offset + size_of::<GenericSdtHeader>()],
                    )
                    .unwrap();
                    if table_header.signature == header.signature {
                        log::info!(
                            "ACPI: {} has been installed, use first\n",
                            core::str::from_utf8(&header.signature).unwrap_or_default()
                        );
                        return;
                    }
                }
                self.table_offset.push(self.size);
            }

            self.acpi_memory[self.size..self.size + table.len()].copy_from_slice(table);
            self.size += table.len();
        }

        fn offset_to_address(&self, offset: usize) -> u64 {
            self.pa + offset as u64
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_acpi_tables() {
            let mut buff = [0u8; 500];
            let mut tables = AcpiTables::new(&mut buff, 0x100000);

            assert_eq!(tables.offset_to_address(0x1000), 0x101000);
            assert_eq!(tables.size, 0);

            tables.install(&[]);
            assert_eq!(tables.size, 0);
            tables.install(&[0u8]);
            assert_eq!(tables.size, 0);
            tables.install(&[0u8; 269]);
            assert_eq!(tables.size, 0);

            let hdr = GenericSdtHeader::new(b"FACP", 44, 2);
            let mut buf = [0u8; 44];
            buf[0..size_of::<GenericSdtHeader>()].copy_from_slice(hdr.as_bytes());
            tables.install(&buf);
            assert_eq!(tables.fadt, Some((0, 44)));
            assert_eq!(tables.size, 44);

            let hdr = GenericSdtHeader::new(b"DSDT", size_of::<GenericSdtHeader>() as u32, 2);
            tables.install(hdr.as_bytes());
            assert_eq!(tables.size, 44 + size_of::<GenericSdtHeader>());

            let hdr = GenericSdtHeader::new(b"TEST", size_of::<GenericSdtHeader>() as u32, 2);
            tables.install(hdr.as_bytes());
            assert_eq!(tables.size, 44 + 2 * size_of::<GenericSdtHeader>());

            let hdr = GenericSdtHeader::new(b"TEST", size_of::<GenericSdtHeader>() as u32, 2);
            tables.install(hdr.as_bytes());
            assert_eq!(tables.size, 44 + 2 * size_of::<GenericSdtHeader>());

            let addr = tables.finish();
            assert_eq!(
                addr,
                0x100000 + 240 + 2 * size_of::<GenericSdtHeader>() as u64
            );
        }
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
        let mut xsdt = Xsdt::new();
        assert_eq!(xsdt.header.length as usize, size_of::<GenericSdtHeader>());
        for idx in 0..ACPI_TABLES_MAX_NUM {
            xsdt.add_table(idx as u64);
            assert_eq!(
                xsdt.header.length as usize,
                size_of::<GenericSdtHeader>() + (idx + 1) * 8
            );
        }

        xsdt.add_table(100);
        assert_eq!(
            xsdt.header.length as usize,
            size_of::<GenericSdtHeader>() + ACPI_TABLES_MAX_NUM * 8
        );
        xsdt.add_table(101);
        assert_eq!(
            xsdt.header.length as usize,
            size_of::<GenericSdtHeader>() + ACPI_TABLES_MAX_NUM * 8
        );
    }
}

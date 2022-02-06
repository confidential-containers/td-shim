// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;
use td_layout::memslice;
use zerocopy::{AsBytes, FromBytes};

const ACPI_TABLES_MAX_NUM: usize = 20;
const ACPI_RSDP_REVISION: u8 = 2;

pub fn calculate_checksum(data: &[u8]) -> u8 {
    (255 - data.iter().fold(0u8, |acc, x| acc.wrapping_add(*x))).wrapping_add(1)
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    _rsdt_addr: u32,
    length: u32,
    xsdt_addr: u64,
    extended_checksum: u8,
    _reserved: [u8; 3],
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
    signature: [u8; 4],
    pub length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

impl GenericSdtHeader {
    pub fn new(signature: [u8; 4], length: u32, revision: u8) -> Self {
        GenericSdtHeader {
            signature,
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

    pub fn checksum(&mut self, checksum: u8) {
        self.checksum = checksum;
    }
}

#[repr(C, packed)]
#[derive(Default, AsBytes, FromBytes)]
struct Xsdt {
    header: GenericSdtHeader,
    tables: [u64; ACPI_TABLES_MAX_NUM],
}

impl Xsdt {
    pub fn new() -> Self {
        Xsdt {
            header: GenericSdtHeader::new(*b"XSDT", size_of::<GenericSdtHeader>() as u32, 1),
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
            panic!("too many ACPI tables, max {}", ACPI_TABLES_MAX_NUM);
        }
    }

    pub fn checksum(&mut self) {
        self.header.checksum(0);
        self.header.checksum(calculate_checksum(
            &self.as_bytes()[..self.header.length as usize],
        ));
    }
}

#[derive(Default)]
pub struct AcpiTables {
    acpi_memory: &'static mut [u8],
    size: usize,
    fadt: Option<(usize, usize)>, // FADT offset in acpi memory
    dsdt: Option<usize>,          // DSDT offset in acpi memory
    table_offset: Vec<usize>,
}

impl AcpiTables {
    pub fn new(td_acpi_mem: &'static mut [u8]) -> Self {
        AcpiTables {
            acpi_memory: td_acpi_mem,
            ..Default::default()
        }
    }

    pub fn finish(&mut self) -> u64 {
        let mut xsdt = Xsdt::new();

        // The Fixed ACPI Description Table (FADT) should always be the first table in XSDT.
        if let Some((fadt_off, fadt_len)) = self.fadt {
            let fadt = &mut self.acpi_memory[fadt_off..fadt_off + fadt_len];
            // The Differentiated System Description Table (DSDT) is referred by the FADT table.
            if let Some(dsdt) = self.dsdt {
                // Safe because DSDT is loaded in acpi_memory which is below 4G
                let dsdt = self.offset_to_address(dsdt) as u32;
                // The DSDT field of FADT [40..44]
                dsdt.write_to(fadt[40..44]);
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
        let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()]).unwrap();

        if &header.signature == b"FACP" {
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
        (self.acpi_memory.as_ptr() as usize + offset) as u64
    }
}

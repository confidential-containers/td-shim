// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
extern crate alloc;
use alloc::vec::Vec;
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

use crate::memslice;

const ACPI_TABLES_MAX_NUM: usize = 20;
const ACPI_RSDP_REVISION: u8 = 2;

pub fn calculate_checksum(data: &[u8]) -> u8 {
    (255 - data.iter().fold(0u8, |acc, x| acc.wrapping_add(*x))).wrapping_add(1)
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
pub struct Rsdp {
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
    }

    fn checksum(&mut self) {
        self.checksum = calculate_checksum(&self.as_bytes()[0..19]);
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
pub struct Xsdt {
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

    pub fn add_table(&mut self, addr: usize) {
        let table_num =
            (self.header.length as usize - size_of::<GenericSdtHeader>()) / size_of::<u64>();
        self.tables[table_num] = addr as u64;
        self.header.length += size_of::<u64>() as u32;
    }

    pub fn checksum(&mut self) {
        self.header.checksum(calculate_checksum(
            &self.as_bytes()[..self.header.length as usize],
        ));
    }
}

#[derive(Default)]
pub struct AcpiTables {
    acpi_memory: &'static mut [u8],
    size: usize,
    fadt: Option<usize>, // FADT offset in acpi memory
    dsdt: Option<usize>, // DSDT offset in acpi memory
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
        // Create XSDT
        let mut xsdt = Xsdt::new();

        // The Fixed ACPI Description Table (FADT) should
        // always be the first table that XSDT points to.
        //
        if let Some(fadt) = self.fadt {
            let fadt_header = GenericSdtHeader::read_from(
                &self.acpi_memory[fadt..fadt + size_of::<GenericSdtHeader>()],
            )
            .unwrap();

            // The Differentiated System Description Table (DSDT) is refered
            // by the FADT table.
            if let Some(dsdt) = self.dsdt {
                let dsdt = dsdt as u32 + self.acpi_memory.as_ptr() as u32;
                // The DSDT field of FADT [40..44]
                // DSDT is loaded in acpi_memory which is below 4G
                dsdt.write_to(&mut self.acpi_memory[fadt + 40..fadt + 44]);
            }

            // Update FADT checksum
            self.acpi_memory[fadt + 9] = 0;
            let fadt_checksum =
                calculate_checksum(&self.acpi_memory[fadt..fadt + fadt_header.length as usize]);
            self.acpi_memory[fadt + 9] = fadt_checksum;

            let fadt = fadt + self.acpi_memory.as_ptr() as usize;
            xsdt.add_table(fadt);
        }

        for offset in &self.table_offset {
            xsdt.add_table(offset + self.acpi_memory.as_ptr() as usize);
        }

        xsdt.checksum();
        xsdt.write_to(&mut self.acpi_memory[self.size..self.size + size_of::<Xsdt>()]);

        //Create RSDP with XSDT addr
        let mut rsdp = Rsdp::new(self.acpi_memory.as_ptr() as u64 + self.size as u64);
        self.size += size_of::<Xsdt>();
        rsdp.write_to(&mut self.acpi_memory[self.size..self.size + size_of::<Rsdp>()]);

        let rsdp_addr = self.acpi_memory.as_ptr() as u64 + self.size as u64;
        self.size += size_of::<Rsdp>();
        rsdp_addr
    }

    pub fn install(&mut self, table: &[u8]) {
        if self.acpi_memory.len() < self.size + table.len() {
            return;
        }

        let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()]).unwrap();

        if (&header.signature == b"FACP") {
            self.fadt = Some(self.size);
        } else if (&header.signature == b"DSDT") {
            self.dsdt = Some(self.size);
        } else {
            for offset in &self.table_offset {
                let table_header = GenericSdtHeader::read_from(
                    &self.acpi_memory[*offset..offset + size_of::<GenericSdtHeader>()],
                )
                .unwrap();
                if table_header.signature == header.signature {
                    log::info!(
                        "ACPI: {} has been installed, use first\n",
                        core::str::from_utf8(&header.signature).unwrap()
                    );
                    return;
                }
            }
            self.table_offset.push(self.size);
        }

        self.acpi_memory[self.size..self.size + table.len()].copy_from_slice(table);
        self.size += table.len();
    }
}

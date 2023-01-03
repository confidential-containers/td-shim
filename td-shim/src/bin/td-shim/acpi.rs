// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::collections::BTreeMap;
use anyhow::*;
use core::ops::Range;
use td_shim::acpi::{calculate_checksum, GenericSdtHeader, Rsdp};

use super::*;

pub type AcpiSignature = [u8; 4];

const DSDT_SIGNATURE: &AcpiSignature = b"DSDT";
const XSDT_SIGNATURE: &AcpiSignature = b"XSDT";
const FADT_SIGNATURE: &AcpiSignature = b"FACP";

const MIN_FADT_LENGTH: u32 = 44;

#[derive(Default)]
pub struct AcpiTables<'a> {
    acpi_memory: &'a mut [u8],
    size: usize,
    tables: BTreeMap<AcpiSignature, Range<usize>>,
}

impl<'a> AcpiTables<'a> {
    pub fn new(acpi_memory: &'a mut [u8]) -> Self {
        AcpiTables {
            acpi_memory,
            ..Default::default()
        }
    }

    pub fn finish(&mut self) -> Result<u64> {
        let fadt_addr = self.tables.remove(FADT_SIGNATURE).map(|r| {
            // Safe because DSDT is loaded in acpi_memory which is below 4G
            let dsdt = self
                .tables
                .remove(DSDT_SIGNATURE)
                .map(|v| self.offset_to_address(v.start))
                .unwrap_or_default() as u32;

            let fadt = &mut self.acpi_memory[r.clone()];
            // The Differentiated System Description Table (DSDT) is referred by the FADT table.
            if dsdt != 0 {
                // The DSDT field of FADT [40..44]
                fadt[40..44].copy_from_slice(&u32::to_le_bytes(dsdt));

                // Update FADT checksum
                fadt[9] = 0;
                fadt[9] = calculate_checksum(fadt);
            }

            fadt.as_ptr() as u64
        });

        let xsdt_addr = self
            .create_xsdt(fadt_addr)
            .ok_or(anyhow!("Failed to create XSDT"))?;
        self.create_rsdp(xsdt_addr)
            .ok_or(anyhow!("Failed to create RSDP"))
    }

    pub fn install(&mut self, table: &[u8]) -> Result<()> {
        // Reserve space for Xsdt and Rsdp
        let reserved_space = size_of::<Rsdp>()
            + size_of::<GenericSdtHeader>()
            + self.tables.len() * size_of::<u64>();

        if self.size.checked_add(table.len()).is_none()
            || table.len() < size_of::<GenericSdtHeader>()
        {
            return Err(anyhow!("Invalid ACPI table"));
        } else if self.acpi_memory.len() - reserved_space < self.size + table.len() {
            return Err(anyhow!("No enough memory to install ACPI tables"));
        }

        // Safe because we have checked buffer size.
        let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()]).unwrap();
        let length = header.length as usize;
        if length > table.len() || length < size_of::<GenericSdtHeader>() {
            return Err(anyhow!("Invalid ACPI table"));
        }

        // Check whether we have already installed the ACPI table with the same signature
        if self.tables.get(&header.signature).is_some() {
            log::warn!(
                "ACPI table: {} has been installed, use the first installed one\n",
                core::str::from_utf8(&header.signature).unwrap_or_default()
            );
            return Ok(());
        }

        // We will write to the `dsdt` fields at [40-44)
        if &header.signature == FADT_SIGNATURE {
            if header.length < MIN_FADT_LENGTH {
                return Err(anyhow!("Invalid ACPI table"));
            }
        }

        let offset = self
            .write_table(table)
            .ok_or(anyhow!("Failed to write ACPI table into ACPI memory"))?;
        self.tables
            .insert(header.signature, offset..offset + table.len());

        Ok(())
    }

    fn write_table(&mut self, table: &[u8]) -> Option<usize> {
        if self.size.checked_add(table.len())? > self.acpi_memory.len() {
            return None;
        }

        let offset = self.size;

        self.acpi_memory[self.size..self.size + table.len()].copy_from_slice(table);
        self.size += table.len();

        Some(offset)
    }

    fn create_xsdt(&mut self, fadt_addr: Option<u64>) -> Option<u64> {
        let mut xsdt = Sdt::new(XSDT_SIGNATURE, 1);

        // The Fixed ACPI Description Table (FADT) should always be the first table in XSDT.
        if let Some(fadt_addr) = fadt_addr {
            xsdt.extend(&u64::to_le_bytes(fadt_addr))
        }

        for (signature, table) in &self.tables {
            if signature != FADT_SIGNATURE && signature != DSDT_SIGNATURE {
                xsdt.extend(&u64::to_le_bytes(self.offset_to_address(table.start)));
            }
        }

        self.write_table(xsdt.as_bytes())
            .and_then(|offset| Some(self.offset_to_address(offset)))
    }

    fn create_rsdp(&mut self, xsdt_addr: u64) -> Option<u64> {
        let rsdp = Rsdp::new(xsdt_addr);
        self.write_table(rsdp.as_bytes())
            .and_then(|offset| Some(self.offset_to_address(offset)))
    }

    fn offset_to_address(&self, offset: usize) -> u64 {
        self.acpi_memory.as_ptr() as u64 + offset as u64
    }
}

pub struct Sdt {
    table: Vec<u8>,
}

impl Sdt {
    pub fn new(signature: &[u8; 4], revision: u8) -> Self {
        let header =
            GenericSdtHeader::new(signature, size_of::<GenericSdtHeader>() as u32, revision);

        let mut table = Vec::new();
        table.extend_from_slice(header.as_bytes());
        table[9] = calculate_checksum(&table);

        Self { table }
    }

    pub fn new_from_bytes(sdt: &[u8]) -> Self {
        let mut table = Vec::new();
        table.extend_from_slice(sdt);

        Self { table }
    }

    pub fn extend(&mut self, data: &[u8]) {
        self.table.extend_from_slice(data);

        let length = self.table.len() as u32;
        self.table[4..8].copy_from_slice(&u32::to_le_bytes(length));
        self.checksum();
    }

    pub fn checksum(&mut self) {
        self.table[9] = 0;
        self.table[9] = calculate_checksum(&self.table);
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.table.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use core::convert::TryInto;

    use super::*;

    #[test]
    fn test_acpi_tables() {
        let mut buff = [0u8; 500];
        let buff_addr = buff.as_ptr() as u64;
        let mut tables = AcpiTables::new(&mut buff);

        assert_eq!(tables.offset_to_address(0x1000), buff_addr + 0x1000);
        assert_eq!(tables.size, 0);

        tables.install(&[]);
        assert_eq!(tables.size, 0);
        tables.install(&[0u8]);
        assert_eq!(tables.size, 0);
        tables.install(&[0u8; 269]);
        assert_eq!(tables.size, 0);

        let hdr = GenericSdtHeader::new(FADT_SIGNATURE, 44, 2);
        let mut buf = [0u8; 44];
        buf[0..size_of::<GenericSdtHeader>()].copy_from_slice(hdr.as_bytes());
        tables.install(&buf);
        assert_eq!(
            tables.tables.get(FADT_SIGNATURE),
            Some(&core::ops::Range { start: 0, end: 44 })
        );
        assert_eq!(tables.size, 44);

        let hdr = GenericSdtHeader::new(DSDT_SIGNATURE, size_of::<GenericSdtHeader>() as u32, 2);
        tables.install(hdr.as_bytes());
        assert_eq!(tables.size, 44 + size_of::<GenericSdtHeader>());

        let hdr = GenericSdtHeader::new(b"TEST", size_of::<GenericSdtHeader>() as u32, 2);
        tables.install(hdr.as_bytes());
        assert_eq!(tables.size, 44 + 2 * size_of::<GenericSdtHeader>());

        let hdr = GenericSdtHeader::new(b"TEST", size_of::<GenericSdtHeader>() as u32, 2);
        tables.install(hdr.as_bytes());
        assert_eq!(tables.size, 44 + 2 * size_of::<GenericSdtHeader>());

        let addr = tables.finish().unwrap();
        // RSDP is intalled after `FADT`, `DSDT`, `TEST` and `XSDT`
        // XSDT contains two pointer point to `FADT` and `TEST`
        // DSDT is pointed by `FADT`
        assert_eq!(
            addr,
            buff_addr
                + MIN_FADT_LENGTH as u64
                + 3 * size_of::<GenericSdtHeader>() as u64
                + size_of::<u64>() as u64 * 2,
        );
    }

    #[test]
    fn test_sdt() {
        const CHECK_SUM: u8 = 26;

        let mut sdt = Sdt::new(b"TEST", 1);
        assert_eq!(sdt.as_bytes().len(), size_of::<GenericSdtHeader>());

        sdt.extend(&[0x2; 0x100]);
        assert_eq!(sdt.as_bytes().len(), size_of::<GenericSdtHeader>() + 0x100);
        assert_eq!(
            sdt.as_bytes().len(),
            u32::from_le_bytes(sdt.as_bytes()[4..8].try_into().unwrap()) as usize
        );

        sdt.checksum();
        assert_eq!(sdt.as_bytes()[9], CHECK_SUM);
    }
}

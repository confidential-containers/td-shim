// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
extern crate alloc;

use td_shim_interface::acpi::{calculate_checksum, Rsdp, Xsdt};

use super::*;

const ACPI_MAX_TABLES: usize = 128;

pub struct AcpiTables<'a> {
    acpi_memory: &'a mut [u8],
    pa: u64,
    size: usize,
    fadt: Option<(usize, usize)>, // FADT offset in acpi memory
    dsdt: Option<usize>,          // DSDT offset in acpi memory
    table_offsets: [usize; ACPI_MAX_TABLES],
    num_tables: usize,
}

impl<'a> AcpiTables<'a> {
    pub fn new(td_acpi_mem: &'a mut [u8], pa: u64) -> Self {
        AcpiTables {
            acpi_memory: td_acpi_mem,
            pa,
            size: 0,
            fadt: None,
            dsdt: None,
            table_offsets: [0; ACPI_MAX_TABLES],
            num_tables: 0,
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
            xsdt.add_table(self.offset_to_address(fadt_off))
                .expect("Unable to add table into XSDT");
        }

        for offset in &self.table_offsets[..self.num_tables] {
            xsdt.add_table(self.offset_to_address(*offset))
                .expect("Unable to add table into XSDT");
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
            panic!(
                "ACPI content size exceeds limit 0x{:X}",
                self.acpi_memory.len(),
            );
        } else if table.len() < size_of::<GenericSdtHeader>() {
            panic!("ACPI table with length 0x{:X} is invalid", table.len());
        }

        // Safe because we have checked buffer size.
        let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()]).unwrap();
        if header.length as usize > table.len() {
            panic!(
                "invalid ACPI table, header length {} is bigger than data length {}",
                header.length as usize,
                table.len()
            );
        }

        if &header.signature == b"FACP" {
            // We will write to the `dsdt` fields at [40-44)
            if header.length < 44 {
                panic!("invalid ACPI FADT table");
            }
            self.fadt = Some((self.size, header.length as usize));
        } else if &header.signature == b"DSDT" {
            self.dsdt = Some(self.size);
        } else {
            for offset in &self.table_offsets[..self.num_tables] {
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
            if self.num_tables >= ACPI_MAX_TABLES {
                panic!("Number of ACPI table exceeds limit 0x{:X}", ACPI_MAX_TABLES,);
            }
            self.table_offsets[self.num_tables] = self.size;
            self.num_tables += 1;
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

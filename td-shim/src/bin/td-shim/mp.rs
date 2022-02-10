// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

use td_shim::acpi::{self, GenericSdtHeader};

// 255 vCPUs needs 2278 bytes, refer to create_madt().
const MADT_MAX_SIZE: usize = 0xc00;
const NUM_8259_IRQS: usize = 16;

const ACPI_1_0_PROCESSOR_LOCAL_APIC: u8 = 0x00;
const ACPI_1_0_IO_APIC: u8 = 0x01;
const ACPI_1_0_INTERRUPT_SOURCE_OVERRIDE: u8 = 0x02;
const ACPI_1_0_LOCAL_APIC_NMI: u8 = 0x04;
const ACPI_MADT_MPWK_STRUCT_TYPE: u8 = 0x10;

pub struct Madt {
    pub data: [u8; MADT_MAX_SIZE],
    pub size: usize,
}

impl Madt {
    fn default() -> Self {
        Madt {
            data: [0; MADT_MAX_SIZE],
            size: 0,
        }
    }

    fn write(&mut self, data: &[u8]) {
        self.data[self.size..self.size + data.len()].copy_from_slice(data);
        self.size += data.len();
    }

    fn update_checksum(&mut self) {
        self.data[9] = 0;
        self.data[9] = acpi::calculate_checksum(&self.data[0..self.size]);
    }
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct LocalApic {
    pub r#type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct LocalApicNmi {
    pub r#type: u8,
    pub length: u8,
    pub acpi_processor_id: u8,
    pub flags: u16,
    pub local_apic_inti: u8,
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct IoApic {
    pub r#type: u8,
    pub length: u8,
    pub ioapic_id: u8,
    _reserved: u8,
    pub apic_address: u32,
    pub gsi_base: u32,
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct InterruptSourceOverride {
    pub r#type: u8,
    pub length: u8,
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct MadtMpwkStruct {
    r#type: u8,
    length: u8,
    mail_box_version: u16,
    reserved: u32,
    mail_box_address: u64,
}

pub fn create_madt(cpu_num: u8, mailbox_base: u64) -> Option<Madt> {
    log::info!("create_madt(): cpu_num: {:x}\n", cpu_num);

    let table_length = size_of::<GenericSdtHeader>()
        + 8
        + cpu_num as usize * size_of::<LocalApic>()
        + size_of::<IoApic>()
        + NUM_8259_IRQS * size_of::<InterruptSourceOverride>()
        + size_of::<LocalApicNmi>()
        + size_of::<MadtMpwkStruct>();
    if cpu_num == 0 || table_length > MADT_MAX_SIZE {
        return None;
    }

    let mut madt = Madt::default();
    let header = GenericSdtHeader::new(b"APIC", table_length as u32, 1);

    // Write generic header
    madt.write(header.as_bytes());

    // Write APIC base and version
    madt.write(&0xfee00000u32.to_le_bytes());
    madt.write(&1u32.to_le_bytes());

    for cpu in 0..cpu_num {
        let lapic = LocalApic {
            r#type: ACPI_1_0_PROCESSOR_LOCAL_APIC,
            length: size_of::<LocalApic>() as u8,
            processor_id: cpu as u8,
            apic_id: cpu as u8,
            flags: 1,
        };
        madt.write(lapic.as_bytes());
    }

    let ioapic = IoApic {
        r#type: ACPI_1_0_IO_APIC,
        length: size_of::<IoApic>() as u8,
        ioapic_id: cpu_num,
        apic_address: 0xFEC00000,
        gsi_base: 0,
        ..Default::default()
    };
    madt.write(ioapic.as_bytes());

    let iso = InterruptSourceOverride {
        r#type: ACPI_1_0_INTERRUPT_SOURCE_OVERRIDE,
        length: size_of::<InterruptSourceOverride>() as u8,
        bus: 0,
        source: 0,
        gsi: 2,
        flags: 5,
    };
    madt.write(iso.as_bytes());

    for irq in 1..NUM_8259_IRQS {
        let iso = InterruptSourceOverride {
            r#type: ACPI_1_0_INTERRUPT_SOURCE_OVERRIDE,
            length: size_of::<InterruptSourceOverride>() as u8,
            bus: 0,
            source: irq as u8,
            gsi: irq as u32,
            flags: 5,
        };
        madt.write(iso.as_bytes());
    }

    let nmi = LocalApicNmi {
        r#type: ACPI_1_0_LOCAL_APIC_NMI,
        length: size_of::<LocalApicNmi>() as u8,
        acpi_processor_id: 0xff,
        flags: 0,
        local_apic_inti: 0x01,
    };
    madt.write(nmi.as_bytes());

    let mpwk = MadtMpwkStruct {
        r#type: ACPI_MADT_MPWK_STRUCT_TYPE,
        length: size_of::<MadtMpwkStruct>() as u8,
        mail_box_version: 1,
        reserved: 0,
        mail_box_address: mailbox_base,
    };
    madt.write(mpwk.as_bytes());

    assert_eq!(madt.size, table_length);
    madt.update_checksum();

    Some(madt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_mdat() {
        assert!(create_madt(0, 0x1000).is_none());
        let madt = create_madt(255, 0x1000).unwrap();
        assert!(madt.size < MADT_MAX_SIZE);
    }
}

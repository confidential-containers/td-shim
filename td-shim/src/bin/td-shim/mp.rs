// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

use td_shim::acpi::{self, GenericSdtHeader};

// 255 vCPUs needs 2278 bytes, refer to create_madt().
const MADT_MAX_SIZE: usize = 0xc00;
const NUM_8259_IRQS: usize = 16;

const ACPI_1_0_PROCESSOR_LOCAL_APIC: u8 = 0x00;
const ACPI_MADT_MPWK_STRUCT_TYPE: u8 = 0x10;
const ACPI_MADT_MPWK_MAILBOX_VERSION: u16 = 0x00;

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

        // Update the length field in header
        self.data[4..8].copy_from_slice(&u32::to_le_bytes(self.size as u32));
        self.update_checksum()
    }

    fn update_checksum(&mut self) {
        self.data[9] = 0;
        self.data[9] = acpi::calculate_checksum(&self.data[0..self.size]);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.size]
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
struct MadtMpwkStruct {
    r#type: u8,
    length: u8,
    mail_box_version: u16,
    reserved: u32,
    mail_box_address: u64,
}

// Create ACPI MADT table based on the one from VMM
// APIC / IRQ information should be provided by VMM
// TD-Shim appends the MP wakeup structure to the table
pub fn create_madt(vmm_madt: &[u8], mailbox_base: u64) -> Option<Madt> {
    if &vmm_madt[0..4] != b"APIC" || vmm_madt.len() < size_of::<GenericSdtHeader>() {
        return None;
    }

    // Safe since we have checked the length
    let len = u32::from_le_bytes(vmm_madt[4..8].try_into().unwrap());

    let mut madt = Madt::default();
    madt.write(&vmm_madt[..len as usize]);

    let mpwk = MadtMpwkStruct {
        r#type: ACPI_MADT_MPWK_STRUCT_TYPE,
        length: size_of::<MadtMpwkStruct>() as u8,
        mail_box_version: ACPI_MADT_MPWK_MAILBOX_VERSION,
        reserved: 0,
        mail_box_address: mailbox_base,
    };
    madt.write(mpwk.as_bytes());

    Some(madt)
}

// If there is no MADT passed from VMM, construct the default
// one which contains the APIC base / version, local APIC and
// MP wakeup structure
pub fn create_madt_default(cpu_num: u32, mailbox_base: u64) -> Option<Madt> {
    log::info!("create_madt(): cpu_num: {:x}\n", cpu_num);

    let table_length = size_of::<GenericSdtHeader>()
        + 8
        + cpu_num as usize * size_of::<LocalApic>()
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

    let mpwk = MadtMpwkStruct {
        r#type: ACPI_MADT_MPWK_STRUCT_TYPE,
        length: size_of::<MadtMpwkStruct>() as u8,
        mail_box_version: ACPI_MADT_MPWK_MAILBOX_VERSION,
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
        assert!(create_madt_default(0, 0x1000).is_none());
        let madt = create_madt_default(255, 0x1000).unwrap();
        assert!(madt.size < MADT_MAX_SIZE);

        let mut vmm_madt = [0u8; size_of::<SdtHeader>()];
        assert!(create_madt(&vmm_madt, 0x1000).is_none());

        vmm_madt[0..4].copy_from_slice(b"APIC");
        let madt = create_madt(&vmm_madt, mailbox).unwrap();
        assert_eq!(madt.size, vmm_madt.len() + size_of::<MadtMpwkStruct>());
    }
}

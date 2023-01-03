// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

use td_shim::acpi::{
    self,
    madt::{LocalApic, MadtMpwkStruct},
    GenericSdtHeader,
};

use crate::acpi::{AcpiSignature, Sdt};

const NUM_8259_IRQS: usize = 16;

const ACPI_1_0_PROCESSOR_LOCAL_APIC: u8 = 0x00;
const ACPI_MADT_MPWK_STRUCT_TYPE: u8 = 0x10;

const MADT_SIGNATURE: &AcpiSignature = b"APIC";
const MADT_REVISION: u8 = 1;

// Create ACPI MADT table based on the one from VMM
// APIC / IRQ information should be provided by VMM
// TD-Shim appends the MP wakeup structure to the table
pub fn create_madt(vmm_madt: &[u8], mailbox_base: u64) -> Option<Sdt> {
    if &vmm_madt[0..4] != MADT_SIGNATURE || vmm_madt.len() < size_of::<GenericSdtHeader>() {
        return None;
    }

    // Safe since we have checked the length
    let len = u32::from_le_bytes(vmm_madt[4..8].try_into().unwrap());

    let mut madt = Sdt::new_from_bytes(&vmm_madt[..len as usize]);

    let mpwk = MadtMpwkStruct {
        r#type: ACPI_MADT_MPWK_STRUCT_TYPE,
        length: size_of::<MadtMpwkStruct>() as u8,
        mail_box_version: 1,
        reserved: 0,
        mail_box_address: mailbox_base,
    };
    madt.extend(mpwk.as_bytes());

    Some(madt)
}

// If there is no MADT passed from VMM, construct the default
// one which contains the APIC base / version, local APIC and
// MP wakeup structure
pub fn create_madt_default(cpu_num: u32, mailbox_base: u64) -> Option<Sdt> {
    log::info!("create_madt(): cpu_num: {:x}\n", cpu_num);

    if cpu_num == 0 || cpu_num > u8::MAX as u32 {
        return None;
    }

    let mut madt = Sdt::new(MADT_SIGNATURE, MADT_REVISION);

    // Write APIC base and version
    madt.extend(&0xfee00000u32.to_le_bytes());
    madt.extend(&1u32.to_le_bytes());

    for cpu in 0..cpu_num {
        let lapic = LocalApic {
            r#type: ACPI_1_0_PROCESSOR_LOCAL_APIC,
            length: size_of::<LocalApic>() as u8,
            processor_id: cpu as u8,
            apic_id: cpu as u8,
            flags: 1,
        };
        madt.extend(lapic.as_bytes());
    }

    let mpwk = MadtMpwkStruct {
        r#type: ACPI_MADT_MPWK_STRUCT_TYPE,
        length: size_of::<MadtMpwkStruct>() as u8,
        mail_box_version: 1,
        reserved: 0,
        mail_box_address: mailbox_base,
    };
    madt.extend(mpwk.as_bytes());

    Some(madt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAILBOX: u64 = 0x100000;

    #[test]
    fn test_create_mdat_default() {
        assert!(create_madt_default(0, MAILBOX).is_none());
        let madt = create_madt_default(255, MAILBOX).unwrap();
        assert_eq!(
            madt.as_bytes().len(),
            size_of::<GenericSdtHeader>()
                + size_of::<u32>() * 2
                + size_of::<LocalApic>() * 255
                + size_of::<MadtMpwkStruct>()
        );
    }

    #[test]
    fn test_create_mdat() {
        let mut vmm_madt = [0u8; size_of::<GenericSdtHeader>()];
        assert!(create_madt(&vmm_madt, MAILBOX).is_none());

        vmm_madt[0..4].copy_from_slice(b"APIC");
        vmm_madt[4..8].copy_from_slice(&u32::to_le_bytes(size_of::<GenericSdtHeader>() as u32));

        let madt = create_madt(&vmm_madt, MAILBOX).unwrap();
        assert_eq!(
            madt.as_bytes().len(),
            vmm_madt.len() + size_of::<MadtMpwkStruct>()
        );

        let mut vmm_madt = [0u8; 0x100];
        vmm_madt[0..4].copy_from_slice(b"APIC");
        vmm_madt[4..8].copy_from_slice(&u32::to_le_bytes(size_of::<GenericSdtHeader>() as u32));

        let madt = create_madt(&vmm_madt, MAILBOX).unwrap();
        assert_eq!(
            madt.as_bytes().len(),
            size_of::<GenericSdtHeader>() + size_of::<MadtMpwkStruct>()
        );
    }
}

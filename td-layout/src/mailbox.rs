// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::ptr::slice_from_raw_parts;
use scroll::{Pread, Pwrite};

/// Size of the OS section at the start of the ACPI MP wakeup mailbox. The rest
/// of the 4 KiB mailbox is reserved for firmware.
pub const MAILBOX_OS_SECTION_SIZE: usize = 0x800;

/// Put the OS section of a mailbox into the idle state that APs expect before
/// the first command: command NOOP, APIC ID invalid, wakeup vector 0, and the
/// remaining OS-owned bytes cleared. The firmware section is not touched.
pub fn reset_mailbox_os_section(os_section: &mut [u8; MAILBOX_OS_SECTION_SIZE]) {
    let idle = TdxMpWakeupMailbox::default();
    os_section.fill(0);
    os_section[..idle.as_bytes().len()].copy_from_slice(idle.as_bytes());
}

#[repr(C)]
#[derive(Pwrite, Pread)]
pub struct TdxMpWakeupMailbox {
    pub command: u16,
    pub rsvd: u16,
    pub apic_id: u32,
    pub wakeup_vector: u64,
}

impl Default for TdxMpWakeupMailbox {
    fn default() -> Self {
        TdxMpWakeupMailbox {
            command: 0,
            rsvd: 0,
            apic_id: 0xffff_ffff,
            wakeup_vector: 0,
        }
    }
}

impl TdxMpWakeupMailbox {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            &*slice_from_raw_parts(
                self as *const TdxMpWakeupMailbox as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryInto;
    use core::mem::size_of;
    use memoffset::offset_of;

    #[test]
    fn ensure_data_struct_size() {
        assert_eq!(size_of::<TdxMpWakeupMailbox>(), 16);
        assert_eq!(offset_of!(TdxMpWakeupMailbox, command), 0);
        assert_eq!(offset_of!(TdxMpWakeupMailbox, apic_id), 4);
        assert_eq!(offset_of!(TdxMpWakeupMailbox, wakeup_vector), 8);
    }

    #[test]
    fn test_tdx_mp_wakeup_mailbox() {
        let default_data: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let mail_box = TdxMpWakeupMailbox::default();
        let mail_box_data = mail_box.as_bytes();
        assert_eq!(mail_box_data, &default_data);

        let mail_box: TdxMpWakeupMailbox = default_data.pread(0).unwrap();
        assert_eq!(mail_box.as_bytes(), &default_data);
    }

    #[test]
    fn test_reset_mailbox_os_section() {
        let mut page = [0xaau8; 0x1000];
        // A pending WAKEUP broadcast to 0x1000, as an AP would see it.
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        page[4..8].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
        page[8..16].copy_from_slice(&0x1000u64.to_le_bytes());

        let os_section: &mut [u8; MAILBOX_OS_SECTION_SIZE] =
            (&mut page[..MAILBOX_OS_SECTION_SIZE]).try_into().unwrap();
        reset_mailbox_os_section(os_section);

        let mail_box: TdxMpWakeupMailbox = page.pread(0).unwrap();
        assert_eq!(mail_box.command, 0);
        assert_eq!(mail_box.apic_id, 0xffff_ffff);
        assert_eq!(mail_box.wakeup_vector, 0);
        assert!(
            page[size_of::<TdxMpWakeupMailbox>()..MAILBOX_OS_SECTION_SIZE]
                .iter()
                .all(|b| *b == 0)
        );
        // The firmware section is left alone.
        assert!(page[MAILBOX_OS_SECTION_SIZE..].iter().all(|b| *b == 0xaa));
    }
}

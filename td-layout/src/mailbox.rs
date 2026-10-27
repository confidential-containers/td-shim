// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::ptr::slice_from_raw_parts;
use scroll::{Pread, Pwrite};

use crate::build_time::{
    TD_SHIM_MAILBOX_BASE, TD_SHIM_MAILBOX_SIZE, TD_SHIM_TEMP_HEAP_BASE, TD_SHIM_TEMP_HEAP_SIZE,
    TD_SHIM_TEMP_STACK_BASE, TD_SHIM_TEMP_STACK_SIZE,
};

// wakeup_vector_in_firmware_scratch() and the reset vector's
// REJECT_FW_SCRATCH_TARGET treat these three regions as one range.
const _: () = assert!(
    TD_SHIM_MAILBOX_BASE + TD_SHIM_MAILBOX_SIZE == TD_SHIM_TEMP_STACK_BASE
        && TD_SHIM_TEMP_STACK_BASE + TD_SHIM_TEMP_STACK_SIZE == TD_SHIM_TEMP_HEAP_BASE
);

/// Return `true` if `vector` points into the firmware's own unmeasured scratch
/// pages (mailbox + temp stack + temp heap, which are contiguous in the image
/// layout).
///
/// The mailbox page is declared `TEMP_MEM` and is therefore not measured, so a
/// malicious VMM controls its initial content. No legitimate AP wakeup target
/// ever lives inside the firmware scratch region, so a wakeup vector pointing
/// there can only be a VMM-planted implant and must be rejected. This mirrors
/// the defense-in-depth check performed by the measured reset-vector assembly
/// (`REJECT_FW_SCRATCH_TARGET`).
///
/// Note: this is a backstop only. It cannot by itself stop the pre-boot mailbox
/// hijack, because a malicious VMM may place its implant in ordinary unmeasured
/// guest RAM instead; the authoritative mitigation is sanitizing the
/// VMM-supplied mailbox state in measured code before it is consumed.
pub fn wakeup_vector_in_firmware_scratch(vector: u64) -> bool {
    let start = TD_SHIM_MAILBOX_BASE as u64;
    let end = TD_SHIM_TEMP_HEAP_BASE as u64 + TD_SHIM_TEMP_HEAP_SIZE as u64;
    vector >= start && vector < end
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
    fn test_wakeup_vector_in_firmware_scratch() {
        let scratch_start = TD_SHIM_MAILBOX_BASE as u64;
        let scratch_end = TD_SHIM_TEMP_HEAP_BASE as u64 + TD_SHIM_TEMP_HEAP_SIZE as u64;

        // Addresses inside the firmware scratch region must be rejected.
        assert!(wakeup_vector_in_firmware_scratch(scratch_start));
        assert!(wakeup_vector_in_firmware_scratch(
            TD_SHIM_TEMP_STACK_BASE as u64
        ));
        assert!(wakeup_vector_in_firmware_scratch(
            TD_SHIM_TEMP_HEAP_BASE as u64
        ));
        assert!(wakeup_vector_in_firmware_scratch(scratch_end - 1));

        // Boundaries and anything outside the region are allowed.
        assert!(!wakeup_vector_in_firmware_scratch(scratch_start - 1));
        assert!(!wakeup_vector_in_firmware_scratch(scratch_end));
        assert!(!wakeup_vector_in_firmware_scratch(0));
        // A legitimate relocated mailbox / OS trampoline in low guest RAM.
        assert!(!wakeup_vector_in_firmware_scratch(0x100_000));
        // Firmware code region (e.g. parallel_accept_memory) is above the scratch.
        assert!(!wakeup_vector_in_firmware_scratch(0xFFCA_F000));
    }
}

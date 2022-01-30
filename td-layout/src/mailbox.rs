// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::ptr::slice_from_raw_parts;
use scroll::{Pread, Pwrite};

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
}

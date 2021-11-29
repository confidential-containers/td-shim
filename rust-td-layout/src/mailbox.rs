// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use scroll::{Pread, Pwrite};

#[repr(C)]
#[derive(Default, Pwrite, Pread)]
pub struct TdxMpWakeupMailbox {
    pub command: u16,
    pub rsvd: u16,
    pub apic_id: u32,
    pub wakeup_vector: u64,
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

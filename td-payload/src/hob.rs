// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::mem::size_of;
use scroll::Pread;
use spin::Once;
use td_shim_interface::td_uefi_pi::{
    hob::check_hob_integrity,
    pi::hob::{HandoffInfoTable, HOB_TYPE_HANDOFF},
};

use crate::Error;

static HOB: Once<&'static [u8]> = Once::new();

pub fn init(ptr: u64) -> Result<&'static [u8], Error> {
    // Get the HOB size from PHIT
    let phit =
        unsafe { core::slice::from_raw_parts(ptr as *const u8, size_of::<HandoffInfoTable>()) }
            .pread::<HandoffInfoTable>(0)
            .map_err(|_| Error::ParseHob)?;

    // Sanity check
    let hob = if phit.header.r#type == HOB_TYPE_HANDOFF
        && phit.header.length as usize >= size_of::<HandoffInfoTable>()
    {
        let size = phit.efi_end_of_hob_list - ptr;
        unsafe { core::slice::from_raw_parts(ptr as *const u8, size as usize) }
    } else {
        return Err(Error::ParseHob);
    };

    let hob = check_hob_integrity(hob).ok_or(Error::ParseHob)?;
    HOB.call_once(|| hob);

    Ok(hob)
}

pub fn get_hob() -> Option<&'static [u8]> {
    HOB.get().copied()
}

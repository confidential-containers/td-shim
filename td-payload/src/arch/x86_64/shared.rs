// Copyright (c) 2022, 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent


#[cfg(feature = "tdcall")]
use crate::mm::SIZE_4K;
#[cfg(feature = "tdcall")]
use tdx_tdcall::tdcall;

#[cfg(feature = "tdvmcall")]
use tdx_tdcall::tdvmcall;

#[cfg(feature = "tdvmcall")]
use super::paging::{clear_shared_bit, set_shared_bit};

#[cfg(feature = "tdvmcall")]
pub fn decrypt(addr: u64, length: usize) {
    set_shared_bit(addr, length);

    // Safety: Fail to map GPA is a fatal error that we cannot handle
    if tdvmcall::mapgpa(true, addr, length).is_err() {
        panic!("Fail to map GPA to shared memory with TDVMCALL");
    }
}

#[cfg(feature = "tdvmcall")]
pub fn encrypt(addr: u64, length: usize) {
    clear_shared_bit(addr, length);

    // Safety: Fail to map GPA is a fatal error that we cannot handle
    if tdvmcall::mapgpa(false, addr, length).is_err() {
        panic!("Fail to map GPA to private memory with TDVMCALL");
    }
    accept_memory(addr, length);
}

#[cfg(feature = "tdcall")]
fn accept_memory(addr: u64, length: usize) {
    let page_num = length / SIZE_4K;

    for p in 0..page_num {
        if let Err(e) = tdcall::accept_page(addr + (p * SIZE_4K) as u64) {
            if let tdcall::TdCallError::LeafSpecific(error_code) = e {
                if error_code == tdcall::TDCALL_STATUS_PAGE_ALREADY_ACCEPTED {
                    continue;
                }
            }
            panic!("Accept page error: 0x{:x}, size: {}\n", addr, length);
        }
    }
}

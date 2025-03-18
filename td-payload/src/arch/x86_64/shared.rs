// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(not(feature = "no-tdaccept"))]
use crate::mm::SIZE_4K;

use tdx_tdcall::tdx;

use super::paging::{clear_shared_bit, set_shared_bit};

#[cfg(not(feature = "no-tdvmcall"))]
pub fn decrypt(addr: u64, length: usize) {
    set_shared_bit(addr, length);

    // Safety: Fail to map GPA is a fatal error that we cannot handle
    if tdx::tdvmcall_mapgpa(true, addr, length).is_err() {
        panic!("Fail to map GPA to shared memory with TDVMCALL");
    }
}

#[cfg(not(feature = "no-tdvmcall"))]
pub fn encrypt(addr: u64, length: usize) {
    clear_shared_bit(addr, length);

    // Safety: Fail to map GPA is a fatal error that we cannot handle
    if tdx_tdcall::tdx::tdvmcall_mapgpa(false, addr, length).is_err() {
        panic!("Fail to map GPA to private memory with TDVMCALL");
    }
    #[cfg(not(feature = "no-tdaccept"))]
    accept_memory(addr, length);
}

#[cfg(feature = "no-tdvmcall")]
pub fn decrypt(addr: u64, length: usize) {
    set_shared_bit(addr, length);
}

#[cfg(feature = "no-tdvmcall")]
pub fn encrypt(addr: u64, length: usize) {
    clear_shared_bit(addr, length);
    #[cfg(not(feature = "no-tdaccept"))]
    accept_memory(addr, length);
}

#[cfg(not(feature = "no-tdaccept"))]
fn accept_memory(addr: u64, length: usize) {
    let page_num = length / SIZE_4K;

    for p in 0..page_num {
        if let Err(e) = tdx::tdcall_accept_page(addr + (p * SIZE_4K) as u64) {
            if let tdx_tdcall::TdCallError::LeafSpecific(error_code) = e {
                if error_code == tdx_tdcall::TDCALL_STATUS_PAGE_ALREADY_ACCEPTED {
                    continue;
                }
            }
            panic!("Accept page error: 0x{:x}, size: {}\n", addr, length);
        }
    }
}

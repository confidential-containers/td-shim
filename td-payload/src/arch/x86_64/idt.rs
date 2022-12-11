// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub use td_exception::idt::*;

pub const PAGE_FAULT_EXCEPTION: u8 = 14;
pub const PAGE_FAULT_IST: u8 = 1;

/// Initialize exception/interrupt handlers.
///
/// # Safety
/// `CS` needs to be set before this function is called
pub unsafe fn init_idt() {
    init();
}

pub fn register(vector: u8, func: unsafe extern "C" fn()) {
    unsafe { register_handler(vector, func) }
}

/// # Safety
///
/// IDT needs to be initialized before this function is called
pub unsafe fn idt_set_ist(vector: u8, index: u8) {
    let idtr = store_idtr();
    let idt_entries = read_idt(&idtr);
    idt_entries[vector as usize].set_ist(index);

    load_idtr(&idtr)
}

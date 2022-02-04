// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

mod consts;
mod frame;
mod page_table;

pub use consts::*;
pub use page_table::{cr3_write, create_mapping, create_mapping_with_flags, set_page_flags};

/// Initialize the page table management subsystem.
pub fn init() {
    frame::init();
}

/// Reserve page table page at physical address `addr`.
pub fn reserve_page(addr: u64) {
    frame::FRAME_ALLOCATOR.lock().reserve(addr);
}

// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

extern crate alloc;

mod consts;
mod frame;
mod page_table;

pub use consts::*;
pub use page_table::{cr3_write, create_mapping, create_mapping_with_flags, set_page_flags};

#[derive(Debug)]
pub enum Error {
    InvalidArguments,
    MappingError(u64, u64), // physical address, frame size
}

type Result<T> = core::result::Result<T, Error>;

/// Initialize the page table management subsystem.
pub fn init(base: u64, size: usize) -> Result<()> {
    if base as usize % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
        return Err(Error::InvalidArguments);
    }

    frame::init(base, size);
    Ok(())
}

/// Reserve page table page at physical address `addr`.
pub fn reserve_page(addr: u64) {
    frame::FRAME_ALLOCATOR.lock().reserve(addr);
}

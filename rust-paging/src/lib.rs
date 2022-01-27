// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

mod consts;
mod frame;
mod page_table;

pub use consts::*;
pub use page_table::{cr3_write, create_mapping, create_mapping_with_flags, set_page_flags};

use rust_td_layout::runtime;
use x86_64::{
    structures::paging::{OffsetPageTable, PageTable},
    PhysAddr, VirtAddr,
};

/// Initialize the page table management subsystem.
pub fn init() {
    frame::init();
}

/// Build page table to map guest physical addres range [0, system_memory_size), the top page table
/// page will be hosted at guest physical address `page_table_memory_base`.
pub fn setup_paging(page_table_memory_base: u64, system_memory_size: u64) {
    let mut pt = unsafe {
        OffsetPageTable::new(
            &mut *(page_table_memory_base as *mut PageTable),
            VirtAddr::new(PHYS_VIRT_OFFSET as u64),
        )
    };

    if page_table_memory_base > system_memory_size
        || page_table_memory_base < runtime::TD_PAYLOAD_PAGE_TABLE_BASE
        || page_table_memory_base > runtime::TD_PAYLOAD_PAGE_TABLE_BASE + PAGE_TABLE_SIZE as u64
        || runtime::TD_PAYLOAD_PAGE_TABLE_BASE + PAGE_TABLE_SIZE as u64 > system_memory_size
    {
        panic!(
            "invalid parameters (0x{:x}, 0x{:x} to setup_paging()",
            page_table_memory_base, system_memory_size
        );
    }

    frame::FRAME_ALLOCATOR
        .lock()
        .reserve(page_table_memory_base);
    page_table::create_mapping(
        &mut pt,
        PhysAddr::new(0),
        VirtAddr::new(0),
        PAGE_SIZE_DEFAULT as u64,
        system_memory_size,
    );
    page_table::cr3_write();
}

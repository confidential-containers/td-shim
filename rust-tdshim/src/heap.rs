// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use linked_list_allocator::LockedHeap;
use log::*;

use crate::{TD_SHIM_TEMP_HEAP_BASE, TD_SHIM_TEMP_HEAP_SIZE};

#[cfg(not(test))]
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Initialize the heap allocator.
pub(super) fn init() {
    let heap_start = TD_SHIM_TEMP_HEAP_BASE as usize;
    let heap_size = TD_SHIM_TEMP_HEAP_SIZE as usize;

    unsafe {
        #[cfg(not(test))]
        HEAP_ALLOCATOR.lock().init(heap_start, heap_size);
    }
    info!(
        "Heap allocator init done: {:#x?}\n",
        heap_start..heap_start + heap_size
    );
}

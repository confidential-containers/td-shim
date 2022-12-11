// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{alloc::Layout, ptr::NonNull};
use linked_list_allocator::LockedHeap;

use super::SIZE_4K;

static FRAME_ALLOCATOR: LockedHeap = LockedHeap::empty();

// Initialize the page table frame allocator
pub fn init_pt_frame_allocator(start: u64, size: usize) {
    unsafe {
        FRAME_ALLOCATOR.lock().init(start as *mut u8, size);
    }
}

/// # Safety
/// The caller needs to explicitly call the `free_pt_frame` function after use
pub unsafe fn alloc_pt_frame() -> Option<usize> {
    let addr = FRAME_ALLOCATOR
        .lock()
        .allocate_first_fit(Layout::from_size_align(SIZE_4K, SIZE_4K).ok()?)
        .map(|ptr| ptr.as_ptr() as usize)
        .ok()?;

    core::slice::from_raw_parts_mut(addr as *mut u8, SIZE_4K).fill(0);

    Some(addr)
}

/// # Safety
/// The caller needs to ensure the correctness of the addr
pub unsafe fn free_pt_frame(addr: usize) {
    FRAME_ALLOCATOR.lock().deallocate(
        NonNull::new(addr as *mut u8).unwrap(),
        Layout::from_size_align(SIZE_4K, SIZE_4K).unwrap(),
    );
}

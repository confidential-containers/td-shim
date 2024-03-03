// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{alloc::Layout, ptr::NonNull};
use linked_list_allocator::LockedHeap;

use super::SIZE_4K;
use crate::arch::shared::{decrypt, encrypt};

static SHARED_MEMORY_ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init_shared_memory(start: u64, size: usize) {
    // Initialize the shared memory allocator
    unsafe {
        SHARED_MEMORY_ALLOCATOR.lock().init(start as *mut u8, size);
    }
}

pub struct SharedMemory {
    addr: usize,
    size: usize,
}

impl SharedMemory {
    pub fn new(num_page: usize) -> Option<Self> {
        let addr = unsafe { alloc_shared_pages(num_page)? };

        Some(Self {
            addr,
            size: num_page * SIZE_4K,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.addr as *const u8, self.size) }
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.addr as *mut u8, self.size) }
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        // Set the shared memory region to be private before it is freed
        encrypt(self.addr as u64, self.size);
        unsafe { free_shared_pages(self.addr, self.size / SIZE_4K) }
    }
}

/// # Safety
/// The caller needs to explicitly call the `free_shared_pages` function after use
pub unsafe fn alloc_shared_pages(num: usize) -> Option<usize> {
    let size = SIZE_4K.checked_mul(num)?;

    let addr = SHARED_MEMORY_ALLOCATOR
        .lock()
        .allocate_first_fit(Layout::from_size_align(size, SIZE_4K).ok()?)
        .map(|ptr| ptr.as_ptr() as usize)
        .ok()?;

    core::slice::from_raw_parts_mut(addr as *mut u8, size).fill(0);

    // Set the shared memory region to be shared
    decrypt(addr as u64, size);

    Some(addr)
}

/// # Safety
/// The caller needs to explicitly call the `free_shared_page` function after use
pub unsafe fn alloc_shared_page() -> Option<usize> {
    alloc_shared_pages(1)
}

/// # Safety
/// The caller needs to ensure the correctness of the addr and page num
pub unsafe fn free_shared_pages(addr: usize, num: usize) {
    let size = SIZE_4K.checked_mul(num).expect("Invalid page num");

    SHARED_MEMORY_ALLOCATOR.lock().deallocate(
        NonNull::new(addr as *mut u8).unwrap(),
        Layout::from_size_align(size, SIZE_4K).unwrap(),
    );
}

/// # Safety
/// The caller needs to ensure the correctness of the addr
pub unsafe fn free_shared_page(addr: usize) {
    free_shared_pages(addr, 1)
}

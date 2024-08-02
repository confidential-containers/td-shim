// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{alloc::Layout, ptr::NonNull};
use linked_list_allocator::LockedHeap;
use spin::Once;

use super::SIZE_4K;
use crate::arch::shared::decrypt;

static SHARED_MEMORY_ALLOCATOR: LockedHeap = LockedHeap::empty();
static SHARED_START: Once<usize> = Once::new();
static SHADOW_START: Once<usize> = Once::new();

pub fn init_shared_memory(start: u64, size: usize) {
    if size % SIZE_4K != 0 {
        panic!("Failed to initialize shared memory: size needs to be aligned with 0x1000");
    }

    // Set the shared memory region to be shared
    decrypt(start, size);
    // Initialize the shared memory allocator
    unsafe {
        SHARED_MEMORY_ALLOCATOR.lock().init(start as *mut u8, size);
    }
}

pub fn init_shared_memory_with_shadow(start: u64, size: usize, shadow_start: u64) {
    init_shared_memory(start, size);
    SHARED_START.call_once(|| start as usize);
    SHADOW_START.call_once(|| shadow_start as usize);
}

pub struct SharedMemory {
    addr: usize,
    shadow_addr: Option<usize>,
    size: usize,
}

impl SharedMemory {
    pub fn new(num_page: usize) -> Option<Self> {
        let addr = unsafe { alloc_shared_pages(num_page)? };
        let shadow_addr = alloc_private_shadow_pages(addr);

        Some(Self {
            addr,
            shadow_addr,
            size: num_page * SIZE_4K,
        })
    }

    pub fn copy_to_private_shadow(&mut self) -> Option<&[u8]> {
        self.shadow_addr.map(|addr| {
            let shadow = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, self.size) };
            shadow.copy_from_slice(self.as_bytes());

            &shadow[..]
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

fn alloc_private_shadow_pages(shared_addr: usize) -> Option<usize> {
    let offset = shared_addr.checked_sub(*SHARED_START.get()?)?;
    Some(SHADOW_START.get()? + offset)
}

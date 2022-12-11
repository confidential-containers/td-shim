// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{alloc::Layout, ptr::NonNull};
use linked_list_allocator::LockedHeap;

use super::SIZE_4K;
use crate::arch::dma::decrypt;

static DMA_ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init_dma(start: u64, size: usize) {
    // Set the DMA memory region to be shared
    decrypt(start, size);
    // Initialize the DMA allocator
    unsafe {
        DMA_ALLOCATOR.lock().init(start as *mut u8, size);
    }
}

pub struct DmaMemory {
    addr: usize,
    size: usize,
}

impl DmaMemory {
    pub fn new(num_page: usize) -> Option<Self> {
        let addr = unsafe { alloc_dma_pages(num_page)? };

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

impl Drop for DmaMemory {
    fn drop(&mut self) {
        unsafe { free_dma_pages(self.addr, self.size / SIZE_4K) }
    }
}

/// # Safety
/// The caller needs to explicitly call the `free_dma_pages` function after use
pub unsafe fn alloc_dma_pages(num: usize) -> Option<usize> {
    let size = SIZE_4K.checked_mul(num)?;

    let addr = DMA_ALLOCATOR
        .lock()
        .allocate_first_fit(Layout::from_size_align(size, SIZE_4K).ok()?)
        .map(|ptr| ptr.as_ptr() as usize)
        .ok()?;

    core::slice::from_raw_parts_mut(addr as *mut u8, SIZE_4K).fill(0);

    Some(addr)
}

/// # Safety
/// The caller needs to explicitly call the `free_dma_page` function after use
pub unsafe fn alloc_dma_page() -> Option<usize> {
    alloc_dma_pages(1)
}

/// # Safety
/// The caller needs to ensure the correctness of the addr and page num
pub unsafe fn free_dma_pages(addr: usize, num: usize) {
    let size = SIZE_4K.checked_mul(num).expect("Invalid page num");

    DMA_ALLOCATOR.lock().deallocate(
        NonNull::new(addr as *mut u8).unwrap(),
        Layout::from_size_align(size, SIZE_4K).unwrap(),
    );
}

/// # Safety
/// The caller needs to ensure the correctness of the addr
pub unsafe fn free_dma_page(addr: usize) {
    free_dma_pages(addr, 1)
}

// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec;
use alloc::vec::Vec;
use spin::{Mutex, Once};

use super::SIZE_4K;
use crate::arch::shared::decrypt;

static SHARED_MEMORY_ALLOCATOR: Mutex<Option<SharedPageAllocator>> = Mutex::new(None);
static SHARED_START: Once<usize> = Once::new();
static SHADOW_START: Once<usize> = Once::new();

// Page allocator for the shared memory region. The allocation state is kept
// in private memory: an allocator that stores its free list inside the free
// blocks (like `linked_list_allocator`) would let the VMM, which can write
// the shared pages at any time, redirect allocations and allocator writes
// into private memory.
struct SharedPageAllocator {
    start: usize,
    used: Vec<bool>,
}

impl SharedPageAllocator {
    fn new(start: usize, size: usize) -> Self {
        Self {
            start,
            used: vec![false; size / SIZE_4K],
        }
    }

    fn alloc(&mut self, num: usize) -> Option<usize> {
        if num == 0 {
            return None;
        }

        let mut free = 0;
        for index in 0..self.used.len() {
            if self.used[index] {
                free = 0;
                continue;
            }
            free += 1;
            if free == num {
                let first = index + 1 - num;
                self.used[first..=index].fill(true);
                return Some(self.start + first * SIZE_4K);
            }
        }

        None
    }

    fn free(&mut self, addr: usize, num: usize) {
        let offset = addr
            .checked_sub(self.start)
            .filter(|offset| offset % SIZE_4K == 0)
            .expect("Invalid shared memory address");
        let first = offset / SIZE_4K;
        let pages = first
            .checked_add(num)
            .and_then(|end| self.used.get_mut(first..end))
            .expect("Invalid shared memory range");
        if pages.iter().any(|used| !used) {
            panic!("Free unallocated shared memory");
        }
        pages.fill(false);
    }
}

pub fn init_shared_memory(start: u64, size: usize) {
    if size % SIZE_4K != 0 {
        panic!("Failed to initialize shared memory: size needs to be aligned with 0x1000");
    }

    // Set the shared memory region to be shared
    decrypt(start, size);
    // Initialize the shared memory allocator
    *SHARED_MEMORY_ALLOCATOR.lock() = Some(SharedPageAllocator::new(start as usize, size));
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

    let addr = SHARED_MEMORY_ALLOCATOR.lock().as_mut()?.alloc(num)?;

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
    SHARED_MEMORY_ALLOCATOR
        .lock()
        .as_mut()
        .expect("Shared memory is not initialized")
        .free(addr, num);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_page_allocator_ignores_shared_contents() {
        let mut shared = vec![0u8; 16 * SIZE_4K];
        let start = shared.as_ptr() as usize;
        let end = start + shared.len();
        let mut allocator = SharedPageAllocator::new(start, shared.len());

        let a = allocator.alloc(15).unwrap();
        assert_eq!(a, start);

        // The VMM can rewrite the free shared pages at any time.
        shared.fill(0xff);

        let b = allocator.alloc(1).unwrap();
        assert!(b >= start && b + SIZE_4K <= end);
        assert!(allocator.alloc(1).is_none());
        assert!(allocator.alloc(4).is_none());

        allocator.free(a, 15);
        let c = allocator.alloc(4).unwrap();
        assert!(c >= start && c + 4 * SIZE_4K <= end);
        assert!(allocator.alloc(0).is_none());
    }

    #[test]
    #[should_panic]
    fn test_shared_page_allocator_rejects_foreign_free() {
        let mut allocator = SharedPageAllocator::new(0x10_0000, 4 * SIZE_4K);
        allocator.alloc(1).unwrap();
        allocator.free(0x10_0000 + 4 * SIZE_4K, 1);
    }

    #[test]
    #[should_panic]
    fn test_shared_page_allocator_rejects_double_free() {
        let mut allocator = SharedPageAllocator::new(0x10_0000, 4 * SIZE_4K);
        let a = allocator.alloc(1).unwrap();
        allocator.free(a, 1);
        allocator.free(a, 1);
    }
}

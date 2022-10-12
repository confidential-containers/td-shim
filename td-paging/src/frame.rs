// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;
use log::{info, trace};
use spin::Mutex;
use x86_64::{
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr,
};

use super::consts::PAGE_SIZE;

/// Global page table page allocator.
pub static FRAME_ALLOCATOR: Mutex<BMFrameAllocator> = Mutex::new(BMFrameAllocator::empty());

struct FrameAlloc {
    //  A bit of `1` means available.
    bitmap: Vec<u128>,
}

impl FrameAlloc {
    fn new(num_frames: usize) -> Self {
        Self {
            bitmap: vec![0u128; (num_frames + 127) / 128],
        }
    }

    fn alloc(&mut self) -> Option<usize> {
        for (idx, map) in self.bitmap.iter_mut().enumerate() {
            let pos = map.trailing_zeros();
            if pos < 128 {
                *map &= !(1 << pos);
                return Some(idx * 128 + pos as usize);
            }
        }

        None
    }

    fn free(&mut self, range: Range<usize>) {
        for idx in range {
            if idx >= self.bitmap.len() * 128 {
                panic!("invalid page frame index {} for FrameAlloc::free()!", idx);
            }
            if self.bitmap[idx / 128] & (1 << (idx % 128)) != 0 {
                panic!(
                    "try to free unallocated page frame index {} for FrameAlloc::free()!",
                    idx
                );
            }
            self.bitmap[idx / 128] |= 1 << (idx % 128);
        }
    }

    fn reserve(&mut self, idx: usize) {
        if idx >= self.bitmap.len() * 128 {
            panic!("invalid page frame index {} for FrameAlloc::free()!", idx);
        }
        if self.bitmap[idx / 128] & (1 << (idx % 128)) == 0 {
            panic!(
                "try to reserve unavailable page frame index {} for FrameAlloc::free()!",
                idx
            );
        }
        self.bitmap[idx / 128] &= !(1 << (idx % 128));
    }
}

pub struct BMFrameAllocator {
    base: usize,
    size: usize,
    inner: FrameAlloc,
}

#[allow(dead_code)]
impl BMFrameAllocator {
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            inner: FrameAlloc { bitmap: Vec::new() },
        }
    }

    // Caller needs to ensure:
    // - base is page aligned
    // - size is page aligned
    // - base + size doesn't wrap around
    fn new(base: usize, size: usize) -> Self {
        let page_count = size / PAGE_SIZE;
        let mut inner = FrameAlloc::new(page_count);

        inner.free(0..page_count);

        Self { base, size, inner }
    }

    fn alloc(&mut self) -> Option<usize> {
        let ret = self.inner.alloc().map(|idx| idx * PAGE_SIZE + self.base);
        trace!("Allocate frame: {:x?}\n", ret);
        ret
    }

    pub(crate) fn reserve(&mut self, addr: u64) {
        if addr > usize::MAX as u64
            || (addr as usize) < self.base
            || (addr as usize) >= self.base + self.size
        {
            panic!(
                "Invalid address 0x{:x} to BMFrameAllocator::reserve()",
                addr
            );
        }
        self.inner.reserve((addr as usize - self.base) / PAGE_SIZE);
    }
}

unsafe impl FrameAllocator<Size4KiB> for BMFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let addr = self.alloc()?;
        Some(PhysFrame::containing_address(
            PhysAddr::try_new(addr as u64).ok()?,
        ))
    }
}

/// Initialize the physical frame allocator.
pub(super) fn init(base: u64, size: usize) {
    let mut allocator = FRAME_ALLOCATOR.lock();
    if allocator.base == 0 && allocator.size == 0 {
        *allocator = BMFrameAllocator::new(base as usize, size);
        // The first frame should've already been allocated to level 4 PT
        // Safe since the PAGE_TABLE_SIZE can be ensured
        allocator.alloc().unwrap();
        info!(
            "Frame allocator init done: {:#x?}\n",
            base..base + size as u64
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_TABLE_BASE: u64 = 0x800000;
    const PAGE_TABLE_SIZE: usize = 0x800000;
    const NUM_PAGE_TABLE_FRAME: usize = PAGE_TABLE_SIZE / PAGE_SIZE;

    #[test]
    fn test_frame_alloc() {
        let mut allocator = FrameAlloc::new(NUM_PAGE_TABLE_FRAME);

        assert_eq!(allocator.bitmap[0] & 0x1, 0);
        assert_eq!(allocator.bitmap[0] & 0x2, 0);
        assert_eq!(allocator.bitmap[0] & 0x4, 0);

        allocator.free(0..3);
        assert_eq!(allocator.bitmap[0] & 0x1, 0x1);
        assert_eq!(allocator.bitmap[0] & 0x2, 0x2);
        assert_eq!(allocator.bitmap[0] & 0x4, 0x4);

        allocator.reserve(0);
        assert_eq!(allocator.bitmap[0] & 0x1, 0x0);
        assert_eq!(allocator.bitmap[0] & 0x2, 0x2);
        assert_eq!(allocator.bitmap[0] & 0x4, 0x4);

        assert_eq!(allocator.alloc().unwrap(), 1);
        assert_eq!(allocator.bitmap[0] & 0x1, 0x0);
        assert_eq!(allocator.bitmap[0] & 0x2, 0x0);
        assert_eq!(allocator.bitmap[0] & 0x4, 0x4);

        allocator.free(1..2);
        assert_eq!(allocator.bitmap[0] & 0x1, 0x0);
        assert_eq!(allocator.bitmap[0] & 0x2, 0x2);
        assert_eq!(allocator.bitmap[0] & 0x4, 0x4);

        assert_eq!(allocator.alloc().unwrap(), 1);
        assert_eq!(allocator.alloc().unwrap(), 2);
        assert!(allocator.alloc().is_none());
        assert!(allocator.alloc().is_none());
    }

    #[test]
    #[should_panic]
    fn test_frame_free_invalid_index() {
        let mut allocator = FrameAlloc::new(NUM_PAGE_TABLE_FRAME);

        allocator.free(0..NUM_PAGE_TABLE_FRAME + 1);
    }

    #[test]
    #[should_panic]
    fn test_frame_free_invalid_state() {
        let mut allocator = FrameAlloc::new(NUM_PAGE_TABLE_FRAME);

        allocator.free(0..3);
        allocator.free(0..3);
    }

    #[test]
    #[should_panic]
    fn test_frame_reserve_invalid_index() {
        let mut allocator = FrameAlloc::new(NUM_PAGE_TABLE_FRAME);

        allocator.reserve(NUM_PAGE_TABLE_FRAME);
    }

    #[test]
    #[should_panic]
    fn test_frame_reserve_invalid_state() {
        let mut allocator = FrameAlloc::new(NUM_PAGE_TABLE_FRAME);

        allocator.free(0..3);
        allocator.reserve(1);
        allocator.reserve(1);
    }

    #[test]
    fn test_empty_bm_allocator() {
        let mut allocator = BMFrameAllocator::empty();
        assert!(allocator.alloc().is_none());
        assert!(allocator.alloc().is_none());
    }

    #[test]
    fn test_bm_allocator() {
        init(PAGE_TABLE_BASE, PAGE_TABLE_SIZE);
        let mut allocator = FRAME_ALLOCATOR.lock();

        // First page has been allocated by init(), try second page
        allocator.reserve(PAGE_TABLE_BASE + PAGE_SIZE as u64);
        allocator.reserve(PAGE_TABLE_BASE + PAGE_TABLE_SIZE as u64 - 1);
        assert_eq!(
            allocator.allocate_frame().unwrap().start_address().as_u64(),
            PAGE_TABLE_BASE + 2 * PAGE_SIZE as u64
        );
    }
}

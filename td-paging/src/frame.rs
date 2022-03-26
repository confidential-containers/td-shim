// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::ops::Range;
use log::{info, trace};
use spin::Mutex;
use x86_64::{
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr,
};

use super::consts::{PAGE_SIZE, PAGE_TABLE_SIZE};
use td_layout::runtime::TD_PAYLOAD_PAGE_TABLE_BASE;

const NUM_PAGE_TABLE_PAGES: usize = PAGE_TABLE_SIZE / PAGE_SIZE;
const BITMAP_ALLOCATOR_ARRAY_SIZE: usize = (NUM_PAGE_TABLE_PAGES + 127) / 128;

/// Global page table page allocator.
pub static FRAME_ALLOCATOR: Mutex<BMFrameAllocator> = Mutex::new(BMFrameAllocator::empty());

#[derive(Default)]
struct FrameAlloc {
    //  A bit of `1` means available.
    bitmap: [u128; BITMAP_ALLOCATOR_ARRAY_SIZE],
}

impl FrameAlloc {
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
            if idx >= NUM_PAGE_TABLE_PAGES {
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
        if idx >= NUM_PAGE_TABLE_PAGES {
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

#[derive(Default)]
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
            inner: FrameAlloc {
                bitmap: [0; BITMAP_ALLOCATOR_ARRAY_SIZE],
            },
        }
    }

    // Caller needs to ensure:
    // - base is page aligned
    // - size is page aligned
    // - base + size doesn't wrap around
    fn new(base: usize, size: usize) -> Self {
        let mut inner = FrameAlloc::default();
        let page_count = size / PAGE_SIZE;

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
        self.alloc()
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr as u64)))
    }
}

/// Initialize the physical frame allocator.
pub(super) fn init() {
    let mut allocator = FRAME_ALLOCATOR.lock();
    if allocator.base == 0 && allocator.size == 0 {
        *allocator = BMFrameAllocator::new(TD_PAYLOAD_PAGE_TABLE_BASE as usize, PAGE_TABLE_SIZE);
        // The first frame should've already been allocated to level 4 PT
        // Safe since the PAGE_TABLE_SIZE can be ensured
        allocator.alloc().unwrap();
        info!(
            "Frame allocator init done: {:#x?}\n",
            TD_PAYLOAD_PAGE_TABLE_BASE..TD_PAYLOAD_PAGE_TABLE_BASE + PAGE_TABLE_SIZE as u64
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configuration() {
        // At least 4-levels of page table pages.
        assert!(NUM_PAGE_TABLE_PAGES > 4);
    }

    #[test]
    fn test_frame_alloc() {
        let mut allocator = FrameAlloc::default();

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
        let mut allocator = FrameAlloc::default();

        allocator.free(0..NUM_PAGE_TABLE_PAGES + 1);
    }

    #[test]
    #[should_panic]
    fn test_frame_free_invalid_state() {
        let mut allocator = FrameAlloc::default();

        allocator.free(0..3);
        allocator.free(0..3);
    }

    #[test]
    #[should_panic]
    fn test_frame_reserve_invalid_index() {
        let mut allocator = FrameAlloc::default();

        allocator.reserve(NUM_PAGE_TABLE_PAGES);
    }

    #[test]
    #[should_panic]
    fn test_frame_reserve_invalid_state() {
        let mut allocator = FrameAlloc::default();

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
        init();
        let mut allocator = FRAME_ALLOCATOR.lock();

        // First page has been allocated by init(), try second page
        allocator.reserve(TD_PAYLOAD_PAGE_TABLE_BASE + PAGE_SIZE as u64);
        allocator.reserve(TD_PAYLOAD_PAGE_TABLE_BASE + PAGE_TABLE_SIZE as u64 - 1);
        assert_eq!(
            allocator.allocate_frame().unwrap().start_address().as_u64(),
            TD_PAYLOAD_PAGE_TABLE_BASE + 2 * PAGE_SIZE as u64
        );
    }
}

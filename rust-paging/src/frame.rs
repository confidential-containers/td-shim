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
use rust_td_layout::runtime::TD_PAYLOAD_PAGE_TABLE_BASE;

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
            self.bitmap[idx / 128] |= 1 << (idx % 128);
        }
    }

    fn reserve(&mut self, idx: usize) {
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
        let base = base / PAGE_SIZE;
        let page_count = size / PAGE_SIZE;

        inner.free(0..page_count);

        Self { base, size, inner }
    }

    /// # Safety
    ///
    /// This function is unsafe because manual deallocation is needed.
    unsafe fn alloc(&mut self) -> Option<usize> {
        let ret = self.inner.alloc().map(|idx| idx * PAGE_SIZE + self.base);
        trace!("Allocate frame: {:x?}\n", ret);
        ret
    }

    pub(crate) fn reserve(&mut self, addr: u64) {
        if addr < self.base as u64 || addr >= (self.base + self.size) as u64 {
            panic!(
                "Invalid address 0x{:x} to BMFrameAllocator::reserve()",
                addr
            );
        }
        let idx = ((addr as usize) - self.base) / PAGE_SIZE;
        self.inner.reserve(idx);
    }
}

unsafe impl FrameAllocator<Size4KiB> for BMFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        unsafe {
            self.alloc()
                .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr as u64)))
        }
    }
}

/// Initialize the physical frame allocator.
pub(super) fn init() {
    *FRAME_ALLOCATOR.lock() =
        BMFrameAllocator::new(TD_PAYLOAD_PAGE_TABLE_BASE as usize, PAGE_TABLE_SIZE);
    info!(
        "Frame allocator init done: {:#x?}\n",
        TD_PAYLOAD_PAGE_TABLE_BASE..TD_PAYLOAD_PAGE_TABLE_BASE + PAGE_TABLE_SIZE as u64
    );
}

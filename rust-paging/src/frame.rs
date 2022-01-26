// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use log::{info, trace};
use spin::Mutex;
use x86_64::{
    align_up,
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr,
};

use super::consts::{PAGE_SIZE, PAGE_TABLE_SIZE};
use rust_td_layout::runtime::TD_PAYLOAD_PAGE_TABLE_BASE;

/// Global page table page allocator.
pub static FRAME_ALLOCATOR: Mutex<BMFrameAllocator> = Mutex::new(BMFrameAllocator::empty());

// Support max 256 * 4096 = 1MB memory.
type FrameAlloc = bitmap_allocator::BitAlloc256;
use bitmap_allocator::BitAlloc;

pub struct BMFrameAllocator {
    base: usize,
    inner: FrameAlloc,
}

#[allow(dead_code)]
impl BMFrameAllocator {
    const fn empty() -> Self {
        Self {
            base: 0,
            inner: FrameAlloc::DEFAULT,
        }
    }

    fn new(base: usize, size: usize) -> Self {
        let mut inner = FrameAlloc::DEFAULT;
        let base = align_up(base as u64, PAGE_SIZE as u64) as usize;
        let page_count = align_up(size as u64, PAGE_SIZE as u64) as usize / PAGE_SIZE;
        inner.insert(0..page_count);
        Self { base, inner }
    }

    /// # Safety
    ///
    /// This function is unsafe because manual deallocation is needed.
    unsafe fn alloc(&mut self) -> Option<usize> {
        let ret = self.inner.alloc().map(|idx| idx * PAGE_SIZE + self.base);
        trace!("Allocate frame: {:x?}\n", ret);
        ret
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

    // The first frame should've already been allocated to level 4 PT
    // Note: this has strong dependency on the implementation detail of BitAlloc.
    unsafe { FRAME_ALLOCATOR.lock().alloc() };

    info!(
        "Frame allocator init done: {:#x?}\n",
        TD_PAYLOAD_PAGE_TABLE_BASE..TD_PAYLOAD_PAGE_TABLE_BASE + PAGE_TABLE_SIZE as u64
    );
}

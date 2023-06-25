// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use lazy_static::lazy_static;
use linked_list_allocator::LockedHeap;
use spin::Mutex;

lazy_static! {
    static ref HEAP_GLOBALS: Mutex<AllocInfo> = Mutex::new(AllocInfo::empty());
}

pub struct Alloc;

/// A type provide functions for profiling heap usage.
///
/// Note: `HeapProfiling::init` must be called before using the heap
///
/// `HeapProfiling::heap_usage()` used to get the maximum heap usage.
///
/// # Example
///
/// ```no_run
/// use td_benchmark::{Alloc, HeapProfiling};
/// #[global_allocator]
/// static ALLOC: td_benchmark::Alloc = td_benchmark::Alloc;
///
/// let heap_base;
/// let heap_size;
///
/// HeapProfiling::init(heap_base, heap_size);
///
/// your_functions();
///
/// let max_heap_size = HeapProfiling::heap_usage().unwrap();
/// ```
//
// The actual heap profiler state is stored in `HEAP_GLOBALS`.
pub struct HeapProfiling;

impl HeapProfiling {
    /// Initializes an empty heap
    ///
    /// # Args
    ///
    /// * `heap_start` is automatically aligned,
    /// * `heap_size` must be large enough to store the required metadata, otherwise this function will panic.
    ///
    /// # Heap allocator implementation is provided by  `linked_list_allocator` crate.
    pub fn init(heap_start: u64, heap_size: usize) {
        let mut heap_info = HEAP_GLOBALS.lock();
        heap_info.init(heap_start, heap_size)
    }

    /// Returns the current maximum heap usage.
    ///
    /// # Example
    ///
    /// ```no_run
    /// HeapProfiling::init(heap_start, heap_size);
    ///
    /// {
    ///     let _ = vec![0;1024];
    ///     let stack_usage = HeapProfiling::heap_usage().unwrap();
    /// }
    /// ```
    pub fn heap_usage() -> Option<usize> {
        let heap_info = HEAP_GLOBALS.lock();
        Some(heap_info.get_max_heap())
    }
}

struct AllocInfo {
    max_heap: usize,
    used_heap: usize,
    inner: LockedHeap,
}

impl AllocInfo {
    pub const fn empty() -> Self {
        Self {
            max_heap: 0,
            used_heap: 0,
            inner: LockedHeap::empty(),
        }
    }

    /// # Safety
    ///
    /// This function must be called at most once and must only be used on an
    /// empty heap.
    ///
    pub fn init(&mut self, heap_start: u64, heap_size: usize) {
        unsafe {
            self.inner.lock().init(heap_start as *mut u8, heap_size);
        }
    }

    pub fn get_max_heap(&self) -> usize {
        self.max_heap
    }
}

unsafe impl GlobalAlloc for Alloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut heap_info = HEAP_GLOBALS.lock();
        let res = heap_info.inner.alloc(layout);
        if !res.is_null() {
            heap_info.used_heap += layout.size();
            if heap_info.max_heap < heap_info.used_heap {
                heap_info.max_heap = heap_info.used_heap;
            }
        }
        res
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut heap_info = HEAP_GLOBALS.lock();
        heap_info.inner.dealloc(ptr, layout);
        heap_info.used_heap -= layout.size();
    }
}

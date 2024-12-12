// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;
#[cfg(feature = "test_heap_size")]
use td_benchmark::Alloc;

#[cfg(feature = "test_heap_size")]
#[global_allocator]
static HEAP: td_benchmark::Alloc = td_benchmark::Alloc;

#[cfg(not(feature = "test_heap_size"))]
#[global_allocator]
static HEAP: LockedHeap = LockedHeap::empty();

#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    use crate::println;

    println!("panic ... {:?}", _info);
    x86_64::instructions::hlt();
    loop {}
}

/// The initialization method for the global heap allocator.
pub fn init_heap(heap_start: u64, heap_size: usize) {
    unsafe {
        #[cfg(not(feature = "test_heap_size"))]
        HEAP.lock().init(heap_start as *mut u8, heap_size);
        #[cfg(feature = "test_heap_size")]
        td_benchmark::HeapProfiling::init(heap_start, heap_size);
    }
}

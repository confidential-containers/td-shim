// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;

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

#[alloc_error_handler]
#[allow(clippy::empty_loop)]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    use crate::println;

    println!("alloc_error ... {:?}", _info);
    x86_64::instructions::hlt();
    loop {}
}

/// The initialization method for the global heap allocator.
pub fn init_heap(heap_start: u64, heap_size: usize) {
    unsafe {
        HEAP.lock().init(heap_start as *mut u8, heap_size);
    }
}

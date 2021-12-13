// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![feature(asm)]
#![allow(unused)]

#[macro_use]
extern crate alloc;

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use linked_list_allocator::LockedHeap;
use rust_td_layout::RuntimeMemoryLayout;
use scroll::Pread;

#[global_allocator]
pub static ALLOCATOR: MyHeap = MyHeap::empty();

// stack guard is enabled and the stack needs add guard size
// for stack layout, please refer to rust-tdshim/src/stack_guard.rs.
// REVISIT: need a better way to remove the duplicated definition here.
const STACK_GUARD_PAGE_SIZE: usize = 0x1000;
const STACK_EXCEPTION_PAGE_SIZE: usize = 0x1000;

// REVISIT: need a better way to determine how to adjust the stack, or remove it.
const STACK_ADJUSTMENT_HACK: usize = 0x8;

const STACK_FILL_PATTERN: u8 = 0x5A;

// NOTE: Below code is NOT thread safe. Please don't use it in any AP.
pub struct MyHeap {
    max_heap: usize,
    used_heap: usize,
    inner: LockedHeap,
}

impl MyHeap {
    pub const fn empty() -> Self {
        Self {
            max_heap: 0,
            used_heap: 0,
            inner: LockedHeap::empty(),
        }
    }

    pub fn init(&self, heap_size: usize, heap_start: usize) {
        unsafe {
            self.inner.lock().init(heap_start, heap_size);
        }
    }
}

// the trait `GlobalAlloc` requires an `unsafe impl` declaration
// NOTE: Below code is NOT thread safe. Please don't use it in any AP.
#[allow(clippy::cast_ref_to_mut)]
unsafe impl GlobalAlloc for MyHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let res = self.inner.alloc(layout);
        if !res.is_null() {
            (*(self as *const MyHeap as *mut MyHeap)).used_heap += layout.size();
            if self.max_heap < self.used_heap {
                (*(self as *const MyHeap as *mut MyHeap)).max_heap = self.used_heap;
            }
        }
        res
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner.dealloc(ptr, layout);
        (*(self as *const MyHeap as *mut MyHeap)).used_heap -= layout.size();
    }
}

#[derive(Default)]
pub struct BenchmarkContext<'a> {
    memory_layout: RuntimeMemoryLayout,
    name: &'a str,
    start_timestamp: u64,
    end_timestamp: u64,
    max_stack: usize,
    max_heap: usize,
}

impl<'a> BenchmarkContext<'a> {
    pub fn new(memory_layout: RuntimeMemoryLayout, name: &'a str) -> Self {
        BenchmarkContext {
            memory_layout,
            name,
            ..Default::default()
        }
    }

    fn runtime_stack_base(&self) -> usize {
        self.memory_layout.runtime_stack_base as usize
            + STACK_GUARD_PAGE_SIZE
            + STACK_EXCEPTION_PAGE_SIZE
    }

    pub fn bench_start(&mut self) {
        let rsp: usize;
        unsafe {
            asm!("mov {}, rsp", out(reg) rsp);
        }
        log::info!("rsp_start: {:x}\n", rsp);
        let stack_buffer = unsafe {
            core::slice::from_raw_parts_mut(
                self.runtime_stack_base() as *const u8 as *mut u8,
                // REVISIT:
                // Debug does not need to subtract stack,
                // release needs to subtract some stack,
                // which may be related to optimization
                rsp - self.runtime_stack_base() - STACK_ADJUSTMENT_HACK,
            )
        };

        for x in stack_buffer.iter_mut() {
            *x = STACK_FILL_PATTERN;
        }

        log::info!("bench start ...\n");
        self.start_timestamp = unsafe { x86::time::rdtsc() };
    }

    pub fn bench_end(&mut self) {
        self.end_timestamp = unsafe { x86::time::rdtsc() };
        log::info!("bench end ...\n");
        let rsp: usize;
        unsafe {
            asm!("mov {}, rsp", out(reg) rsp);
        }
        log::info!("rsp_end: {:x}\n", rsp);
        let stack_buffer = unsafe {
            core::slice::from_raw_parts_mut(
                self.runtime_stack_base() as *const u8 as *mut u8,
                // REVISIT:
                // Debug does not need to subtract stack,
                // release needs to subtract some stack,
                // which may be related to optimization
                rsp - self.runtime_stack_base() - STACK_ADJUSTMENT_HACK,
            )
        };

        let max_stack_used = detect_stack_in_buffer(stack_buffer).unwrap();
        self.max_stack = max_stack_used;

        log::info!(" delta: {}\n", self.end_timestamp - self.start_timestamp);
        log::info!("detect max stack size is: 0x{:0x}\n", self.max_stack);
        log::info!("detect max heap size is: 0x{:0x}\n\n", ALLOCATOR.max_heap);
    }
}

fn detect_stack_in_buffer(buffer: &[u8]) -> Option<usize> {
    let expected_value: u64 = STACK_FILL_PATTERN as u64
        | (STACK_FILL_PATTERN as u64) << 8
        | (STACK_FILL_PATTERN as u64) << 16
        | (STACK_FILL_PATTERN as u64) << 24
        | (STACK_FILL_PATTERN as u64) << 32
        | (STACK_FILL_PATTERN as u64) << 40
        | (STACK_FILL_PATTERN as u64) << 48
        | (STACK_FILL_PATTERN as u64) << 56;
    for i in 0..(buffer.len() / 8) {
        let value: u64 = buffer.pread(i * 8).unwrap();
        if value != expected_value {
            return Some(buffer.len() - i * 8);
        }
    }
    None
}

// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::arch::asm;
use lazy_static::lazy_static;
use spin::Mutex;

lazy_static! {
    static ref STACK_GLOBALS: Mutex<StackInfo> = Mutex::new(StackInfo::default());
}

#[derive(Debug, Default)]
struct StackInfo {
    pub base: usize,
    pub mark: u64,
    pub mark_stack_size: usize,
}

/// A type provide functions for profiling stack usage.
///
/// Profiling starts after init is called.
/// `StackProfiling::stack_usage()` should be call after `StackProfiling::init()`
//
// The actual stack profiler state is stored in `STACK_GLOBALS`.
pub struct StackProfiling;

impl StackProfiling {
    /// Initialize `StackProfiling`.
    ///
    /// # Arguments
    ///
    /// * `mark` - a magic value to fill the stack memory.
    /// * `mark_stack_size` - size of stack memory filled with mark value.
    ///
    /// # Example
    ///
    /// ```
    /// use td_benchmark::StackProfiling;
    /// StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0x1A0000);
    /// ```
    pub fn init(mark: u64, mark_stack_size: usize) {
        let base = mark_stack(mark, mark_stack_size);
        let mut stack_info = STACK_GLOBALS.lock();
        stack_info.base = base;
        stack_info.mark = mark;
        stack_info.mark_stack_size = mark_stack_size;
    }

    /// Returns the current maximum stack usage.
    ///
    /// # Example
    ///
    /// ```
    /// use td_benchmark::StackProfiling;
    /// StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0x1A0000);
    ///
    /// {
    ///     let a = [0;1024];
    ///     let stack_usage = StackProfiling::stack_usage().unwrap();
    /// }
    /// ```
    pub fn stack_usage() -> Option<usize> {
        let stack_info = STACK_GLOBALS.lock();
        calculate_stack_usage(stack_info.base, stack_info.mark, stack_info.mark_stack_size)
    }
}

fn mark_stack(mark: u64, mark_stack_size: usize) -> usize {
    let rsp: usize;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp);
    }
    let base = rsp - mark_stack_size;
    let len = mark_stack_size / 8;
    let buffer = unsafe { core::slice::from_raw_parts_mut(base as *mut u64, len) };
    for v in buffer.iter_mut() {
        *v = mark;
    }
    base
}

fn calculate_stack_usage(base: usize, mark: u64, mark_stack_size: usize) -> Option<usize> {
    let len = mark_stack_size / 8;
    let buffer = unsafe { core::slice::from_raw_parts(base as *mut u64, len) };
    let mut max_stack_size = mark_stack_size;
    for (i, v) in buffer.iter().enumerate().take(len) {
        if *v != mark {
            max_stack_size = mark_stack_size - i * 8;
            break;
        }
    }
    if max_stack_size == mark_stack_size {
        None
    } else {
        Some(max_stack_size)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn stack_use() {
        let max_stack_size = 0x12_0000;
        let mark = 0x5a5a5a5a5a5a5a5a;
        let base_stack_address = mark_stack(mark, max_stack_size);
        function_use_stack();
        let stack_use = calculate_stack_usage(base_stack_address, mark, max_stack_size).unwrap();
        assert!(stack_use > 0x5000 && stack_use < 0x6000)
    }

    #[test]
    fn stack_use_profiling() {
        let max_stack_size = 0x12_0000;
        let mark = 0x5a5a5a5a5a5a5a5a;
        StackProfiling::init(mark, max_stack_size);
        function_use_stack();
        let stack_use = StackProfiling::stack_usage().unwrap();
        assert!(stack_use > 0x5000 && stack_use < 0x6000)
    }

    #[test]
    fn stack_use_invalid() {
        StackProfiling::init(0, 0);
        StackProfiling::stack_usage();
    }

    fn function_use_stack() {
        alloca::with_alloca(
            0x5000, /* how much bytes we want to allocate on stack*/
            |memory: &mut [core::mem::MaybeUninit<u8>]| {
                for m in memory.iter_mut() {
                    m.write(0x1);
                }
            },
        );
    }
}

// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]

use core::any;
use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;

pub mod serial;

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
}

#[global_allocator]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init_heap(heap_start: usize, heap_size: usize) {
    unsafe {
        ALLOCATOR.lock().init(heap_start, heap_size);
    }
}

/// Unit test runner to hook the rust test harness.
///
/// The `custom_test_frameworks` feature allows the use of `#[test_case]` and `#![test_runner]`.
/// Any function, const, or static can be annotated with `#[test_case]` causing it to be aggregated
/// (like #[test]) and be passed to the test runner determined by the `#![test_runner]` crate
/// attribute.
pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
    exit_qemu(QemuExitCode::Success);
}

/// Trait for unit test functions.
pub trait Testable {
    fn run(&self);
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        serial_print!("{}...\t", any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

/// Notify qemu hypervisor to exit, with exit code.
#[allow(clippy::empty_loop)]
pub fn exit_qemu(exit_code: QemuExitCode) -> ! {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }

    loop {}
}

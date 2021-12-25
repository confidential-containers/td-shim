// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![no_std]
#![no_main]
#![allow(unused)]
#![feature(alloc_error_handler)]
#[macro_use]
extern crate alloc;
use core::ffi::c_void;
use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;
use tdx_tdcall::tdx;

#[cfg(not(test))]
#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    log::info!("panic ... {:?}\n", _info);
    loop {}
}

#[alloc_error_handler]
#[allow(clippy::empty_loop)]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    log::info!("alloc_error ... {:?}\n", _info);
    panic!("deadloop");
}

#[cfg(not(test))]
#[global_allocator]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(test))]
pub fn init_heap(heap_start: usize, heap_size: usize) {
    unsafe {
        ALLOCATOR.lock().init(heap_start, heap_size);
    }
}

#[cfg(not(test))]
#[no_mangle]
#[cfg_attr(target_os = "uefi", export_name = "efi_main")]
pub extern "win64" fn _start(hob: *const c_void) -> ! {
    tdx_logger::init();
    log::info!("Starting rust-tdcall-payload hob - {:p}\n", hob);

    let mut td_info = tdx::TdInfoReturnData {
        gpaw: 0,
        attributes: 0,
        max_vcpus: 0,
        num_vcpus: 0,
        rsvd: [0; 3],
    };
    tdx::tdcall_get_td_info(&mut td_info);

    log::info!("gpaw - {:?}\n", td_info.gpaw);
    log::info!("attributes - {:?}\n", td_info.attributes);
    log::info!("max_vcpus - {:?}\n", td_info.max_vcpus);
    log::info!("num_vcpus - {:?}\n", td_info.num_vcpus);
    log::info!("rsvd - {:?}\n", td_info.rsvd);

    // Page fault
    unsafe {
        let pointer: *const u32 = 0x10000000000usize as *const core::ffi::c_void as *const u32;
        let data = *pointer;
        log::info!("test - data: {:x}", data);
    }
    panic!("deadloop");
}

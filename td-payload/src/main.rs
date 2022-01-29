// Copyright © 2019 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
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
#![cfg_attr(not(test), no_main)]
#![feature(global_asm)]
#![feature(asm)]
#![allow(unused)]

#[macro_use]
extern crate alloc;

mod mp;
#[cfg(feature = "benches")]
mod stack;

mod asm;
extern "win64" {
    fn stack_guard_test();

    #[cfg(feature = "cet-ss")]
    fn cet_ss_test(count: usize);
}

#[cfg(not(test))]
mod payload_impl {
    use super::*;
    use core::ffi::c_void;
    use core::panic::PanicInfo;
    use td_layout::memslice;
    use td_layout::runtime::*;
    use uefi_pi::pi::hob_lib;

    #[cfg(feature = "benches")]
    use benchmark::ALLOCATOR;
    #[cfg(not(feature = "benches"))]
    use linked_list_allocator::LockedHeap;

    #[cfg(not(feature = "benches"))]
    #[global_allocator]
    pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

    fn init_heap(heap_start: usize, heap_size: usize) {
        #[cfg(feature = "benches")]
        {
            log::info!("init_heap benches");
            ALLOCATOR.init(heap_start, heap_size);
        }

        #[cfg(not(feature = "benches"))]
        unsafe {
            ALLOCATOR.lock().init(heap_start, heap_size);
        }
    }

    #[panic_handler]
    #[allow(clippy::empty_loop)]
    fn panic(_info: &PanicInfo) -> ! {
        log::info!("panic ... {:?}\n", _info);
        loop {}
    }

    #[no_mangle]
    #[cfg_attr(target_os = "uefi", export_name = "efi_main")]
    pub extern "win64" fn _start(hob: *const c_void) -> ! {
        tdx_logger::init().expect("td-payload: failed to initialize tdx logger");
        log::info!("Starting td-payload hob - {:p}\n", hob);
        log::info!("setup_exception_handlers done\n");

        let hob_buffer = unsafe {
            memslice::get_dynamic_mem_slice_mut(memslice::SliceType::PayloadHob, hob as usize)
        };
        let hob_size = hob_lib::get_hob_total_size(hob_buffer).unwrap();
        let hob_list = &hob_buffer[..hob_size];
        hob_lib::dump_hob(hob_list);

        let heap_start = hob_lib::get_system_memory_size_below_4gb(hob_list).unwrap() as usize
            - (TD_PAYLOAD_HOB_SIZE
                + TD_PAYLOAD_STACK_SIZE
                + TD_PAYLOAD_SHADOW_STACK_SIZE
                + TD_PAYLOAD_ACPI_SIZE
                + TD_PAYLOAD_EVENT_LOG_SIZE) as usize
            - TD_PAYLOAD_HEAP_SIZE as usize;
        init_heap(heap_start, TD_PAYLOAD_HEAP_SIZE as usize);
        let memory_layout = td_layout::RuntimeMemoryLayout::new(
            hob_lib::get_system_memory_size_below_4gb(hob_list).unwrap(),
        );
        assert_eq!(
            (heap_start - TD_PAYLOAD_HEAP_SIZE as usize) as u64,
            memory_layout.runtime_heap_base
        );

        #[cfg(feature = "benches")]
        {
            stack::bench_stack(memory_layout);
        }

        //Dump TD Report
        tdx_tdcall::tdreport::tdreport_dump();

        //Test JSON function using no-std serd_json.
        td_payload::json_test();

        //Stack guard test
        unsafe { stack_guard_test() };

        //Memory Protection (WP & NX) test.
        mp::mp_test();

        // Cet is not enabled by vcpu for now
        #[cfg(feature = "cet-ss")]
        unsafe {
            cet_ss_test(1000)
        };

        unsafe {
            let pointer: *const u32 = 0x10000000000usize as *const core::ffi::c_void as *const u32;
            let data = *pointer;
            log::info!("test - data: {:x}", data);
        }

        panic!("td-payload: all tests finished and enters dead loop");
    }
}

#[cfg(test)]
fn main() {}

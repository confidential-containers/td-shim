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
// This function will cause page fault by memory protection.

use alloc::vec::Vec;

pub fn mp_test() {
    static mut INS: [u8; 2] = [0xEB, 0xFE];

    // Test NX on payload data sections
    unsafe {
        let address = INS.as_ptr() as u64;
        log::info!("NX test address: {:x}\n", address);
        let nx = &address as *const u64 as *const fn();
        (*nx)();
    }

    // Test NX on heap
    unsafe {
        let ins_heap: Vec<u8> = vec![0xEB, 0xFE];
        let address = ins_heap.as_ptr() as u64;
        log::info!("NX test address: {:x}\n", address);
        let nx = &address as *const u64 as *const fn();
        (*nx)();
    }

    // Test WP on a hardcode payload code section (PE)
    unsafe {
        let ptr_to_wp: *mut u32 = 0x403_3000 as *mut core::ffi::c_void as *mut u32;
        *ptr_to_wp = 0x1000;
    }
}

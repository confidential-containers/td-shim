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

use benchmark::BenchmarkContext;
use td_layout::RuntimeMemoryLayout;

fn test_stack() {
    let mut a = [0u8; 0x3000];
    for i in a.iter_mut() {
        *i = 0xcc;
    }
    let rsp: usize;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp);
    }
    log::info!("rsp_test: {:x}\n", rsp);
    let b = vec![1u8, 2, 3, 4];
    log::info!("test stack!!!!!!!!\n");
    log::info!("a: {:x}\n", a.as_ptr() as usize);
    log::info!("b: {:p}\n", &b);
}

pub fn bench_stack(memory_layout: RuntimeMemoryLayout) {
    let mut bench = BenchmarkContext::new(memory_layout, "stack");
    bench.bench_start();
    test_stack();
    bench.bench_end();
}

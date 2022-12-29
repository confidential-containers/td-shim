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

use td_benchmark::StackProfiling;
use td_payload::{mm::layout::DEFAULT_STACK_SIZE, println};

fn test_stack() {
    let mut a = [0u8; 0x3000];
    for i in a.iter_mut() {
        *i = 0xcc;
    }
    let rsp: usize;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp);
    }
    println!("Testa RSP: {:x}\n", rsp);
    let b = vec![1u8, 2, 3, 4];
}

pub fn bench_stack(memory_layout: RuntimeMemoryLayout) {
    StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0x20_0000);
    test_stack();
    let stack_usage = StackProfiling::stack_usage().unwrap();
    println!("Stack bench result: {:#x}\n", stack_usage);
}

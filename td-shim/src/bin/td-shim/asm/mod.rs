// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use core::arch::global_asm;

global_asm!(include_str!("switch_stack.asm"));
global_asm!(include_str!("msr64.asm"));
global_asm!(include_str!("ap_loop.asm"));

extern "win64" {
    fn ap_relocated_func();
    fn ap_relocated_func_end();
}

pub fn ap_relocated_func_addr() -> u64 {
    ap_relocated_func as *const fn() as u64
}

pub fn ap_relocated_func_size() -> u64 {
    ap_relocated_func_end as *const fn() as u64 - ap_relocated_func as *const fn() as u64
}

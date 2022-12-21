// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use core::arch::global_asm;

global_asm!(include_str!("switch_stack.asm"));
global_asm!(include_str!("msr64.asm"));
global_asm!(include_str!("ap_loop.asm"));
global_asm!(include_str!("exception.asm"));

extern "C" {
    fn ap_relocated_func();
    fn ap_relocated_func_end();
    pub fn empty_exception_handler();
    fn empty_exception_handler_end();
}

pub fn ap_relocated_func_addr() -> u64 {
    ap_relocated_func as *const fn() as u64
}

pub fn ap_relocated_func_size() -> u64 {
    ap_relocated_func_end as *const fn() as u64 - ap_relocated_func as *const fn() as u64
}

pub fn empty_exception_handler_size() -> usize {
    empty_exception_handler_end as *const fn() as usize
        - empty_exception_handler as *const fn() as usize
}

// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
global_asm!(include_str!("switch_stack.asm"));
global_asm!(include_str!("msr64.asm"));
global_asm!(include_str!("ap_loop.asm"));

extern "win64" {
    pub fn ap_relocated_func_size(size: *mut u64);
    pub fn ap_relocated_func();
}

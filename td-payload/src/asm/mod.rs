// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use core::arch::global_asm;

global_asm!(include_str!("stack_guard_test.asm"));
#[cfg(feature = "cet-ss")]
global_asm!(include_str!("cet_ss_test.asm"));

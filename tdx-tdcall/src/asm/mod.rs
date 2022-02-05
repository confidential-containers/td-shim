// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "use_tdx_emulation")]
global_asm!(include_str!("tdcall_emu.asm"));

#[cfg(feature = "use_tdx_emulation")]
global_asm!(include_str!("tdvmcall_emu.asm"));

#[cfg(not(feature = "use_tdx_emulation"))]
global_asm!(include_str!("tdcall.asm"));

#[cfg(not(feature = "use_tdx_emulation"))]
global_asm!(include_str!("tdvmcall.asm"));

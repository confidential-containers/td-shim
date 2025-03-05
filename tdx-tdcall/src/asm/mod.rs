// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use core::arch::global_asm;
use core::ffi::c_void;

#[cfg(all(feature = "use_tdx_emulation", feature = "tdcall"))]
global_asm!(include_str!("tdcall_emu.asm"));

#[cfg(all(feature = "use_tdx_emulation", feature = "tdvmcall"))]
global_asm!(include_str!("tdvmcall_emu.asm"));

#[cfg(all(not(feature = "use_tdx_emulation"), feature = "tdcall"))]
global_asm!(include_str!("tdcall.asm"));

#[cfg(all(not(feature = "use_tdx_emulation"), feature = "tdvmcall"))]
global_asm!(include_str!("tdvmcall.asm"));

extern "win64" {
    #[cfg(feature = "tdcall")]
    pub(crate) fn asm_td_call(args: *mut c_void) -> u64;
    #[cfg(feature = "tdvmcall")]
    pub(crate) fn asm_td_vmcall(args: *mut c_void, do_sti: u64) -> u64;
}

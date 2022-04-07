// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

#[cfg(feature = "use_tdx_emulation")]
pub const USE_TDX_EMULATION: bool = true;
#[cfg(not(feature = "use_tdx_emulation"))]
pub const USE_TDX_EMULATION: bool = false;

pub mod asm;
pub mod tdreport;
pub mod tdx;

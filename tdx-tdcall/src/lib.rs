// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Guest-Side (TDCALL) Interface Helper Functions
//!
//! This crate implements the helper functions for the TDCALL interface functions defined in
//! Intel TDX Module specifiction and the TDVMCALL sub-functions defined in Intel TDX
//! Guest-Hypervisor Communication Interface specification. It also provides the constants
//! and data structures that are defined in the specifications.
//!
//! Please refer to following links for detail:
//! [Intel TDX Module v1.0 Spec](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf)
//! [Intel TDX Module v1.5 Spec](https://www.intel.com/content/dam/develop/external/us/en/documents/intel-tdx-module-1.5-abi-spec-348551001.pdf)
//! [Intel TDX Guest-Hypervisor Communication Interface Spec](https://cdrdv2.intel.com/v1/dl/getContent/726790)
//! [Intel TDX Guest-Hypervisor Communication Interface Spec v1.5](https://cdrdv2.intel.com/v1/dl/getContent/726792)
//!
//! A subset of TDCALL interface functions is defined in crate::tdx, and the TDG.MR.REPORT
//! leaf function and TDREPORT_STRUCT related definitions are defined in crate::tdreport
//! separately.

#![no_std]

use core::ffi::c_void;

#[cfg(feature = "use_tdx_emulation")]
pub const USE_TDX_EMULATION: bool = true;
#[cfg(not(feature = "use_tdx_emulation"))]
pub const USE_TDX_EMULATION: bool = false;

pub mod asm;
#[cfg(feature = "tdcall")]
pub mod tdcall;
#[cfg(feature = "tdcall")]
pub mod tdreport;
#[cfg(feature = "tdvmcall")]
pub mod tdvmcall;

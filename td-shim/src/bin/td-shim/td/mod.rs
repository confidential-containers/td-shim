// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "tdcall")]
mod tdx;
#[cfg(feature = "tdcall")]
mod tdx_mailbox;
#[cfg(feature = "tdcall")]
pub use tdx::*;

#[cfg(not(feature = "tdcall"))]
mod dummy;
#[cfg(not(feature = "tdcall"))]
pub use dummy::*;

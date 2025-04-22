// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "tdx")]
mod tdx;
#[cfg(all(feature = "tdx", not(feature = "no-mailbox")))]
mod tdx_mailbox;
#[cfg(feature = "tdx")]
pub use tdx::*;

#[cfg(not(feature = "tdx"))]
mod dummy;
#[cfg(not(feature = "tdx"))]
pub use dummy::*;

// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! UEFI Platform Initialization data structures and accessors.
//!
//! This crate defines constants and data structures defined by the
//! [UEFI-PI Spec](https://uefi.org/sites/default/files/resources/PI_Spec_1_6.pdf)
//! and needed by the `td-shim` project. It also provides functions to parse those data structures
//! from raw data buffer.
//!
//! Constants and data structures defined by [UEFI PI Spec] are hosted by [crate::pi], functions
//! to access them are hosted by [crate::fv] and [crate::hob].

pub mod fv;
pub mod hob;
pub mod pi;

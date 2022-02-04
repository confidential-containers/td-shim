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

//! Boot mode defined in [UEFI-PI Spec](https://uefi.org/sites/default/files/resources/PI_Spec_1_6.pdf),
//! section "4.3 Boot Mode Services".
pub type BootMode = u32;

pub const BOOT_WITH_FULL_CONFIGURATION: u32 = 0x00;
pub const BOOT_WITH_MINIMAL_CONFIGURATION: u32 = 0x01;
pub const BOOT_ASSUMING_NO_CONFIGURATION_CHANGES: u32 = 0x02;
pub const BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS: u32 = 0x03;
pub const BOOT_WITH_DEFAULT_SETTINGS: u32 = 0x04;
pub const BOOT_ON_S4_RESUME: u32 = 0x05;
pub const BOOT_ON_S5_RESUME: u32 = 0x06;
pub const BOOT_WITH_MFG_MODE_SETTINGS: u32 = 0x07;
pub const BOOT_ON_S2_RESUME: u32 = 0x10;
pub const BOOT_ON_S3_RESUME: u32 = 0x11;
pub const BOOT_ON_FLASH_UPDATE: u32 = 0x12;
pub const BOOT_IN_RECOVERY_MODE: u32 = 0x20;

// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spin::Mutex;

use crate::arch::serial;

pub static CONSOLE: Mutex<Console> = Mutex::new(Console {});

pub struct Console;

impl core::fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial::serial_write_string(s);
        Ok(())
    }
}

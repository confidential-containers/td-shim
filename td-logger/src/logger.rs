// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::fmt;
use lazy_static::lazy_static;
use spin::Mutex;

use crate::{dbg_port_write, dbg_write_string};

pub const LOG_LEVEL_VERBOSE: usize = 1000;
pub const LOG_LEVEL_INFO: usize = 100;
pub const LOG_LEVEL_WARN: usize = 10;
pub const LOG_LEVEL_ERROR: usize = 1;
pub const LOG_LEVEL_NONE: usize = 0;

pub const LOG_MASK_COMMON: u64 = 0x1;
// Core - Boot Service (BIT1 ~ BIT15)
pub const LOG_MASK_PROTOCOL: u64 = 0x2;
pub const LOG_MASK_MEMORY: u64 = 0x4;
pub const LOG_MASK_EVENT: u64 = 0x8;
pub const LOG_MASK_IMAGE: u64 = 0x10;
// Core - Runtime Service (BIT16 ~ BIT 23)
pub const LOG_MASK_VARIABLE: u64 = 0x10000;
// Core - Console (BIT24 ~ BIT 31)
pub const LOG_MASK_CONOUT: u64 = 0x1000000;
pub const LOG_MASK_CONIN: u64 = 0x2000000;
// Protocol - (BIT32 ~ BIT63)
pub const LOG_MASK_BLOCK_IO: u64 = 0x100000000;
pub const LOG_MASK_FILE_SYSTEM: u64 = 0x200000000;
// All
pub const LOG_MASK_ALL: u64 = 0xFFFFFFFFFFFFFFFF;

// Use lazy_static here to prevent potential problems caused by compiler/linker optimization.
lazy_static! {
    pub static ref LOGGER: Mutex<Logger> = Mutex::new(Logger {
        level: LOG_LEVEL_VERBOSE,
        mask: LOG_MASK_ALL,
    });
}

pub struct Logger {
    level: usize,
    mask: u64,
}

impl Logger {
    pub fn write_byte(&mut self, byte: u8) {
        dbg_port_write(byte);
    }

    pub fn write_string(&mut self, s: &str) {
        dbg_write_string(s);
    }

    pub fn get_level(&self) -> usize {
        self.level
    }
    pub fn set_level(&mut self, level: usize) {
        self.level = level;
    }

    pub fn get_mask(&self) -> u64 {
        self.mask
    }
    pub fn set_mask(&mut self, mask: u64) {
        self.mask = mask;
    }
}

impl fmt::Write for Logger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

pub fn _log_ex(level: usize, mask: u64, args: fmt::Arguments) {
    if level > LOGGER.lock().get_level() {
        return;
    }
    if (mask & LOGGER.lock().get_mask()) == 0 {
        return;
    }
    _log(args);
}

pub fn _log(args: fmt::Arguments) {
    use core::fmt::Write;
    LOGGER.lock().write_fmt(args).unwrap();
}

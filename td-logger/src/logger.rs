// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! A standalone logger to directly log messages, independent of the log crate.

use core::fmt::{self, Write};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::{dbg_port_write, dbg_write_string};

pub const LOG_LEVEL_TRACE: usize = 5;
pub const LOG_LEVEL_DEBUG: usize = 4;
pub const LOG_LEVEL_INFO: usize = 3;
pub const LOG_LEVEL_WARN: usize = 2;
pub const LOG_LEVEL_ERROR: usize = 1;
pub const LOG_LEVEL_NONE: usize = 0;

pub const LOG_MASK_COMMON: u64 = 0x1;
pub const LOG_MASK_ALL: u64 = 0xFFFFFFFFFFFFFFFF;

// Use lazy_static here to prevent potential problems caused by compiler/linker optimization.
lazy_static! {
    pub static ref LOGGER: Mutex<Logger> = Mutex::new(Logger {
        level: LOG_LEVEL_INFO,
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

/// Log the message with level and subsystem filtering.
pub fn _log_ex(level: usize, mask: u64, args: fmt::Arguments) {
    let mut logger = LOGGER.lock();
    if level <= logger.get_level() && mask & logger.get_mask() != 0 {
        logger.write_fmt(args).unwrap();
    }
}

/// Log the message without level and subsystem filtering.
pub fn _log(args: fmt::Arguments) {
    LOGGER.lock().write_fmt(args).unwrap();
}

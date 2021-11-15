// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![forbid(unsafe_code)]

use log::{Level, Metadata, Record};
use log::{LevelFilter, SetLoggerError};

mod logger;

macro_rules! tdxlog {
    ($($arg:tt)*) => (crate::logger::_log_ex(crate::logger::LOG_LEVEL_VERBOSE, crate::logger::LOG_MASK_COMMON, format_args!($($arg)*)));
}

pub struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            tdxlog!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: Logger = Logger;

fn dbg_port_write(byte: u8) {
    tdx_tdcall::tdx::tdvmcall_io_write_8(0x3F8, byte);
}

pub fn dbg_write_byte(byte: u8) {
    if byte == b'\n' {
        dbg_port_write(b'\r')
    }
    dbg_port_write(byte)
}

pub fn dbg_write_string(s: &str) {
    for c in s.chars() {
        dbg_write_byte(c as u8);
    }
}

pub fn init() -> Result<(), SetLoggerError> {
    dbg_write_string("logger init\n");
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info))
}
